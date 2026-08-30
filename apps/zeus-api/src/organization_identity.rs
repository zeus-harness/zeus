#![allow(clippy::missing_errors_doc)] // HTTP failures use the shared Problem Details contract.

use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    routing::{delete, get, post},
};
use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use time::OffsetDateTime;
use utoipa::ToSchema;
use uuid::Uuid;
use zeus_core::Permission;
use zeus_identity::normalize_email;

use crate::{
    AppState,
    auth::AuthContext,
    crypto::{random_token, sha256},
    database::{TenantScope, begin_tenant},
    error::ApiError,
    native_auth::{AcceptedIdentityResponse, queue_invitation_email_on},
};

#[derive(Debug, Deserialize, ToSchema)]
pub struct InvitationWorkspaceRequest {
    pub workspace_id: Uuid,
    pub role: String,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateInvitationRequest {
    pub email: String,
    pub organization_role: String,
    #[serde(default)]
    pub workspaces: Vec<InvitationWorkspaceRequest>,
}

#[derive(Debug, Serialize, ToSchema, FromRow)]
pub struct InvitationResponse {
    pub id: Uuid,
    pub organization_id: Uuid,
    pub invited_by: Uuid,
    pub accepted_by: Option<Uuid>,
    pub email: String,
    pub organization_role: String,
    pub status: String,
    #[serde(with = "time::serde::rfc3339")]
    pub expires_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339::option")]
    pub accepted_at: Option<OffsetDateTime>,
    #[serde(with = "time::serde::rfc3339::option")]
    pub revoked_at: Option<OffsetDateTime>,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

#[derive(Debug, FromRow)]
struct CreatedInvitationRow {
    id: Uuid,
    organization_name: String,
}

#[utoipa::path(get, path = "/api/v1/organizations/{organization_id}/invitations", tag = "identity",
    params(("organization_id" = Uuid, Path)),
    responses((status = 200, description = "Organization invitations", body = [InvitationResponse]))
)]
pub async fn list_invitations(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(organization_id): Path<Uuid>,
) -> Result<Json<Vec<InvitationResponse>>, ApiError> {
    auth.require_organization(organization_id, Permission::ManageOrganization)?;
    let mut transaction = begin_tenant(
        &state.database,
        TenantScope::organization(auth.user_id, organization_id),
    )
    .await?;
    sqlx::query(
        "update organization_invitations
         set status = 'expired', updated_at = now()
         where organization_id = $1 and status = 'pending' and expires_at <= now()",
    )
    .bind(organization_id)
    .execute(&mut *transaction)
    .await?;
    let invitations = sqlx::query_as::<_, InvitationResponse>(
        "select id, organization_id, invited_by, accepted_by, email,
                organization_role, status, expires_at, accepted_at, revoked_at, created_at
         from organization_invitations
         where organization_id = $1
         order by created_at desc, id desc
         limit 200",
    )
    .bind(organization_id)
    .fetch_all(&mut *transaction)
    .await?;
    transaction.commit().await?;
    Ok(Json(invitations))
}

#[utoipa::path(post, path = "/api/v1/organizations/{organization_id}/invitations", tag = "identity",
    params(("organization_id" = Uuid, Path)),
    request_body = CreateInvitationRequest,
    responses((status = 201, description = "Organization invitation created", body = InvitationResponse))
)]
pub async fn create_invitation(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(organization_id): Path<Uuid>,
    Json(request): Json<CreateInvitationRequest>,
) -> Result<(StatusCode, Json<InvitationResponse>), ApiError> {
    auth.require_organization(organization_id, Permission::ManageOrganization)?;
    let user_id = auth.user_id.ok_or(ApiError::Forbidden)?;
    let email = normalize_email(&request.email)
        .map_err(|_| ApiError::Validation("email is invalid".to_owned()))?;
    validate_organization_role(&request.organization_role)?;
    validate_workspace_grants(&request.workspaces)?;
    let token = random_token(32).map_err(|_| ApiError::Internal)?;
    let expires_at = OffsetDateTime::now_utc() + time::Duration::days(7);

    let mut transaction = begin_tenant(
        &state.database,
        TenantScope::organization(auth.user_id, organization_id),
    )
    .await?;
    let created = sqlx::query_as::<_, CreatedInvitationRow>(
        "with created as (
           insert into organization_invitations (
             organization_id, invited_by, email, organization_role, token_hash, expires_at
           ) values ($1, $2, $3, $4, $5, $6)
           returning id
         )
         select created.id, o.name as organization_name
         from created cross join organizations o
         where o.id = $1",
    )
    .bind(organization_id)
    .bind(user_id)
    .bind(&email)
    .bind(&request.organization_role)
    .bind(sha256(token.expose_secret().as_bytes()))
    .bind(expires_at)
    .fetch_one(&mut *transaction)
    .await?;
    for workspace in &request.workspaces {
        let inserted = sqlx::query(
            "insert into organization_invitation_workspaces (
               invitation_id, organization_id, workspace_id, workspace_role
             )
             select $1, $2, w.id, $4
             from workspaces w
             where w.id = $3 and w.organization_id = $2 and w.status = 'active'",
        )
        .bind(created.id)
        .bind(organization_id)
        .bind(workspace.workspace_id)
        .bind(&workspace.role)
        .execute(&mut *transaction)
        .await?;
        if inserted.rows_affected() != 1 {
            return Err(ApiError::Validation(
                "an invitation workspace is unavailable".to_owned(),
            ));
        }
    }
    let invitation = sqlx::query_as::<_, InvitationResponse>(
        "select id, organization_id, invited_by, accepted_by, email,
                organization_role, status, expires_at, accepted_at, revoked_at, created_at
         from organization_invitations where id = $1",
    )
    .bind(created.id)
    .fetch_one(&mut *transaction)
    .await?;
    queue_invitation_email_on(
        &state,
        &mut transaction,
        &email,
        token.expose_secret(),
        &created.organization_name,
    )
    .await?;
    transaction.commit().await?;
    Ok((StatusCode::CREATED, Json(invitation)))
}

#[derive(Debug, FromRow)]
struct PendingInvitationRow {
    email: String,
    organization_name: String,
}

#[utoipa::path(post, path = "/api/v1/organizations/{organization_id}/invitations/{invitation_id}/resend", tag = "identity",
    params(("organization_id" = Uuid, Path), ("invitation_id" = Uuid, Path)),
    responses((status = 202, description = "Invitation resend accepted", body = AcceptedIdentityResponse))
)]
pub async fn resend_invitation(
    State(state): State<AppState>,
    auth: AuthContext,
    Path((organization_id, invitation_id)): Path<(Uuid, Uuid)>,
) -> Result<(StatusCode, Json<AcceptedIdentityResponse>), ApiError> {
    auth.require_organization(organization_id, Permission::ManageOrganization)?;
    let token = random_token(32).map_err(|_| ApiError::Internal)?;
    let mut transaction = begin_tenant(
        &state.database,
        TenantScope::organization(auth.user_id, organization_id),
    )
    .await?;
    let invitation = sqlx::query_as::<_, PendingInvitationRow>(
        "update organization_invitations i
         set token_hash = $3, expires_at = now() + interval '7 days', updated_at = now()
         from organizations o
         where i.id = $1 and i.organization_id = $2 and i.status = 'pending'
           and o.id = i.organization_id
         returning i.email, o.name as organization_name",
    )
    .bind(invitation_id)
    .bind(organization_id)
    .bind(sha256(token.expose_secret().as_bytes()))
    .fetch_optional(&mut *transaction)
    .await?
    .ok_or(ApiError::NotFound)?;
    queue_invitation_email_on(
        &state,
        &mut transaction,
        &invitation.email,
        token.expose_secret(),
        &invitation.organization_name,
    )
    .await?;
    transaction.commit().await?;
    Ok((
        StatusCode::ACCEPTED,
        Json(AcceptedIdentityResponse::generic()),
    ))
}

#[utoipa::path(delete, path = "/api/v1/organizations/{organization_id}/invitations/{invitation_id}", tag = "identity",
    params(("organization_id" = Uuid, Path), ("invitation_id" = Uuid, Path)),
    responses((status = 204, description = "Invitation revoked"))
)]
pub async fn revoke_invitation(
    State(state): State<AppState>,
    auth: AuthContext,
    Path((organization_id, invitation_id)): Path<(Uuid, Uuid)>,
) -> Result<StatusCode, ApiError> {
    auth.require_organization(organization_id, Permission::ManageOrganization)?;
    let mut transaction = begin_tenant(
        &state.database,
        TenantScope::organization(auth.user_id, organization_id),
    )
    .await?;
    let result = sqlx::query(
        "update organization_invitations
         set status = 'revoked', revoked_at = now(), updated_at = now()
         where id = $1 and organization_id = $2 and status = 'pending'",
    )
    .bind(invitation_id)
    .bind(organization_id)
    .execute(&mut *transaction)
    .await?;
    if result.rows_affected() != 1 {
        return Err(ApiError::NotFound);
    }
    transaction.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

pub fn routes() -> Router<AppState> {
    Router::new()
        .route(
            "/api/v1/organizations/{organization_id}/invitations",
            get(list_invitations).post(create_invitation),
        )
        .route(
            "/api/v1/organizations/{organization_id}/invitations/{invitation_id}/resend",
            post(resend_invitation),
        )
        .route(
            "/api/v1/organizations/{organization_id}/invitations/{invitation_id}",
            delete(revoke_invitation),
        )
}

fn validate_organization_role(role: &str) -> Result<(), ApiError> {
    if matches!(role, "owner" | "admin" | "member" | "auditor") {
        Ok(())
    } else {
        Err(ApiError::Validation(
            "organization_role is invalid".to_owned(),
        ))
    }
}

fn validate_workspace_grants(grants: &[InvitationWorkspaceRequest]) -> Result<(), ApiError> {
    if grants.len() > 100 {
        return Err(ApiError::Validation(
            "an invitation may include at most 100 workspaces".to_owned(),
        ));
    }
    let mut seen = std::collections::BTreeSet::new();
    for grant in grants {
        if !matches!(
            grant.role.as_str(),
            "admin" | "builder" | "operator" | "viewer"
        ) {
            return Err(ApiError::Validation("workspace role is invalid".to_owned()));
        }
        if !seen.insert(grant.workspace_id) {
            return Err(ApiError::Validation(
                "workspace invitation grants must be unique".to_owned(),
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use uuid::Uuid;

    use super::{
        InvitationWorkspaceRequest, validate_organization_role, validate_workspace_grants,
    };

    #[test]
    fn invitation_roles_and_workspace_grants_are_bounded() {
        assert!(validate_organization_role("admin").is_ok());
        assert!(validate_organization_role("platform_admin").is_err());
        let duplicate = vec![
            InvitationWorkspaceRequest {
                workspace_id: Uuid::nil(),
                role: "viewer".to_owned(),
            },
            InvitationWorkspaceRequest {
                workspace_id: Uuid::nil(),
                role: "builder".to_owned(),
            },
        ];
        assert!(validate_workspace_grants(&duplicate).is_err());
    }
}
