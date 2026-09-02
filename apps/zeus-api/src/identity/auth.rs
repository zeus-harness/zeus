#![allow(clippy::missing_errors_doc)] // HTTP failures use the shared Problem Details contract.

use std::collections::BTreeSet;

use axum::{
    Json, Router,
    extract::{FromRequestParts, Path, Query, State},
    http::{HeaderMap, HeaderValue, Method, Request, StatusCode, header, request::Parts},
    middleware::Next,
    response::{IntoResponse, Response},
    routing::{get, post},
};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use subtle::ConstantTimeEq;
use time::OffsetDateTime;
use utoipa::ToSchema;
use uuid::Uuid;
use zeus_core::{OrganizationRole, Permission, WorkspaceRole};
use zeus_identity::PasswordExecutorError;

use crate::{
    AppState,
    crypto::{SealedSecret, random_token, sha256},
    database::{TenantScope, begin_tenant},
    error::ApiError,
    oidc::{
        OidcFlow, OidcProviderConfig, PendingOidcAuthorization, VerifiedOidcIdentity,
        sanitize_return_to,
    },
};

const SESSION_COOKIE: &str = "zeus_session";
const CSRF_COOKIE: &str = "zeus_csrf";
const TENANT_ACCESS_GRANT_COOKIE: &str = "zeus_tenant_access_grant";
const CSRF_HEADER: &str = "x-zeus-csrf";
const SERVICE_ACCOUNT_PREFIX: &str = "zsa_";
const KNOWN_SERVICE_ACCOUNT_SCOPES: &[&str] = &[
    "organization:manage",
    "workspace:manage",
    "workspace:read",
    "workflow:write",
    "run:operate",
    "approval:write",
    "experience:publish",
    "audit:read",
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PrincipalKind {
    User,
    ServiceAccount,
}

#[derive(Clone, Debug)]
pub struct AuthContext {
    pub principal_kind: PrincipalKind,
    pub principal_id: Uuid,
    pub user_id: Option<Uuid>,
    pub session_id: Option<Uuid>,
    pub tenant_access_grant_id: Option<Uuid>,
    pub tenant_access_reason: Option<String>,
    pub tenant_access_expires_at: Option<OffsetDateTime>,
    pub organization_id: Uuid,
    pub workspace_id: Option<Uuid>,
    pub organization_role: Option<OrganizationRole>,
    pub workspace_role: Option<WorkspaceRole>,
    pub scopes: BTreeSet<String>,
    pub email: Option<String>,
    pub display_name: String,
    pub authenticated_at: Option<OffsetDateTime>,
    pub mfa_satisfied_at: Option<OffsetDateTime>,
    pub platform_roles: BTreeSet<String>,
}

#[derive(Clone, Debug)]
pub struct PrincipalContext {
    pub principal_kind: PrincipalKind,
    pub principal_id: Uuid,
    pub user_id: Option<Uuid>,
    pub session_id: Option<Uuid>,
    pub tenant_access_grant_id: Option<Uuid>,
    pub tenant_access_reason: Option<String>,
    pub tenant_access_expires_at: Option<OffsetDateTime>,
    pub organization_status: Option<String>,
    pub organization_id: Option<Uuid>,
    pub workspace_id: Option<Uuid>,
    pub organization_role: Option<OrganizationRole>,
    pub workspace_role: Option<WorkspaceRole>,
    pub scopes: BTreeSet<String>,
    pub email: Option<String>,
    pub display_name: String,
    pub email_verified_at: Option<OffsetDateTime>,
    pub platform_roles: BTreeSet<String>,
    pub auth_methods: BTreeSet<String>,
    pub authenticated_at: Option<OffsetDateTime>,
    pub mfa_satisfied_at: Option<OffsetDateTime>,
    pub idle_expires_at: Option<OffsetDateTime>,
    pub absolute_expires_at: Option<OffsetDateTime>,
    pub(crate) csrf_token_hash: Option<Vec<u8>>,
}

impl AuthContext {
    #[must_use]
    pub fn tenant_scope(&self, workspace_id: Option<Uuid>) -> TenantScope {
        TenantScope {
            user_id: self.user_id,
            session_id: self.session_id,
            organization_id: self.organization_id,
            workspace_id,
            tenant_access_grant_id: self.tenant_access_grant_id,
        }
    }

    /// Verifies organization ownership and permission.
    ///
    /// # Errors
    ///
    /// Returns `403` when the principal belongs to another organization or lacks permission.
    pub fn require_organization(
        &self,
        organization_id: Uuid,
        permission: Permission,
    ) -> Result<(), ApiError> {
        if self.organization_id != organization_id || !self.allows_organization(permission) {
            return if self.platform_roles.contains("platform_owner") {
                Err(ApiError::PlatformTenantAccessRequired)
            } else {
                Err(ApiError::Forbidden)
            };
        }
        Ok(())
    }

    /// Verifies the selected workspace and permission.
    ///
    /// # Errors
    ///
    /// Returns `403` when the principal is not scoped to the workspace or lacks permission.
    pub fn require_workspace(
        &self,
        workspace_id: Uuid,
        permission: Permission,
    ) -> Result<(), ApiError> {
        if self.workspace_id != Some(workspace_id) || !self.allows_workspace(permission) {
            return Err(ApiError::Forbidden);
        }
        Ok(())
    }

    /// Requires a user session that completed authentication within ten minutes.
    ///
    /// Service accounts cannot satisfy an interactive reauthentication check.
    pub fn require_recent_authentication(&self) -> Result<(), ApiError> {
        if self.principal_kind != PrincipalKind::User {
            return Err(ApiError::Forbidden);
        }
        let most_recent = [self.authenticated_at, self.mfa_satisfied_at]
            .into_iter()
            .flatten()
            .max();
        if most_recent
            .is_some_and(|value| OffsetDateTime::now_utc() - value <= time::Duration::minutes(10))
        {
            Ok(())
        } else {
            Err(ApiError::ReauthenticationRequired)
        }
    }

    fn allows_organization(&self, permission: Permission) -> bool {
        if self.tenant_access_grant_id.is_some() {
            return true;
        }
        match self.principal_kind {
            PrincipalKind::User => self
                .organization_role
                .is_some_and(|role| role.allows(permission)),
            PrincipalKind::ServiceAccount => {
                self.workspace_id.is_none() && self.scope_allows(permission)
            }
        }
    }

    fn allows_workspace(&self, permission: Permission) -> bool {
        if self.tenant_access_grant_id.is_some() {
            return true;
        }
        match self.principal_kind {
            PrincipalKind::User => self
                .workspace_role
                .is_some_and(|role| role.allows(permission)),
            PrincipalKind::ServiceAccount => self.scope_allows(permission),
        }
    }

    fn scope_allows(&self, permission: Permission) -> bool {
        let required = match permission {
            Permission::ManageOrganization => "organization:manage",
            Permission::ManageWorkspace => "workspace:manage",
            Permission::BuildWorkflow => "workflow:write",
            Permission::OperateRun => "run:operate",
            Permission::ApproveTool => "approval:write",
            Permission::PublishWorkspaceExperience | Permission::PublishOrganizationExperience => {
                "experience:publish"
            }
            Permission::ReadAudit => "audit:read",
            Permission::ReadWorkspace => "workspace:read",
        };
        self.scopes.contains(required)
    }
}

/// Requires an Organization Owner whose identity settings are not platform-managed.
///
/// The database policies repeat this check so a concurrent governance change cannot
/// authorize an identity write after this stable API error has been selected.
pub async fn require_self_service_identity_settings(
    state: &AppState,
    auth: &AuthContext,
    organization_id: Uuid,
) -> Result<(), ApiError> {
    auth.require_organization(organization_id, Permission::ManageOrganization)?;
    let mut transaction = begin_tenant(&state.platform.database, auth.tenant_scope(None)).await?;
    let mode = sqlx::query_scalar::<_, String>(
        "select identity_settings_mode
         from organization_governance
         where organization_id = $1",
    )
    .bind(organization_id)
    .fetch_optional(&mut *transaction)
    .await?
    .ok_or(ApiError::Internal)?;
    transaction.commit().await?;
    if mode == "self_service" || auth.tenant_access_grant_id.is_some() {
        Ok(())
    } else {
        Err(ApiError::OrganizationIdentitySettingsManaged)
    }
}

impl FromRequestParts<AppState> for AuthContext {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let is_write = !matches!(parts.method, Method::GET | Method::HEAD | Method::OPTIONS);
        let principal = PrincipalContext::from_request_parts(parts, state).await?;
        if principal.principal_kind == PrincipalKind::User {
            if principal.email_verified_at.is_none() {
                return Err(ApiError::EmailVerificationRequired);
            }
            if principal.mfa_satisfied_at.is_none()
                && principal_requires_mfa(state, &principal).await?
            {
                return Err(ApiError::MfaRequired);
            }
            if principal.tenant_access_grant_id.is_none()
                && let Some(provider_id) = required_federated_provider(state, &principal).await?
                && !principal
                    .auth_methods
                    .contains(&format!("federated:{provider_id}"))
            {
                return Err(ApiError::FederatedAuthenticationRequired);
            }
        }
        let organization_id = principal.organization_id.ok_or_else(|| {
            if principal.platform_roles.contains("platform_owner") {
                ApiError::PlatformTenantAccessRequired
            } else {
                ApiError::Forbidden
            }
        })?;
        let organization_status = if let Some(status) = principal.organization_status.as_deref() {
            status.to_owned()
        } else {
            load_organization_status(state, &principal, organization_id).await?
        };
        match organization_status.as_str() {
            "provisioning" => return Err(ApiError::OrganizationProvisioning),
            "suspended" if is_write => {
                return Err(ApiError::OrganizationSuspended);
            }
            "active" | "suspended" => {}
            "archived" => return Err(ApiError::NotFound),
            _ => return Err(ApiError::Internal),
        }
        Ok(Self {
            principal_kind: principal.principal_kind,
            principal_id: principal.principal_id,
            user_id: principal.user_id,
            session_id: principal.session_id,
            tenant_access_grant_id: principal.tenant_access_grant_id,
            tenant_access_reason: principal.tenant_access_reason,
            tenant_access_expires_at: principal.tenant_access_expires_at,
            organization_id,
            workspace_id: principal.workspace_id,
            organization_role: principal.organization_role,
            workspace_role: principal.workspace_role,
            scopes: principal.scopes,
            email: principal.email,
            display_name: principal.display_name,
            authenticated_at: principal.authenticated_at,
            mfa_satisfied_at: principal.mfa_satisfied_at,
            platform_roles: principal.platform_roles,
        })
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct PrincipalMfaStatus {
    required: bool,
    totp_enabled: bool,
}

async fn principal_mfa_status(
    state: &AppState,
    principal: &PrincipalContext,
) -> Result<PrincipalMfaStatus, ApiError> {
    let user_id = principal.user_id.ok_or(ApiError::Forbidden)?;
    let totp_enabled = user_has_totp(state, user_id).await?;
    if principal.platform_roles.contains("platform_owner") || totp_enabled {
        return Ok(PrincipalMfaStatus {
            required: true,
            totp_enabled,
        });
    }
    let Some(organization_id) = principal.organization_id else {
        return Ok(PrincipalMfaStatus {
            required: false,
            totp_enabled,
        });
    };
    let mut transaction = crate::database::begin_tenant(
        &state.platform.database,
        TenantScope::organization(Some(user_id), organization_id),
    )
    .await?;
    let required: bool = sqlx::query_scalar(
        "select coalesce((
           select mfa_required from organization_identity_policies
           where organization_id = $1
         ), false)",
    )
    .bind(organization_id)
    .fetch_one(&mut *transaction)
    .await?;
    transaction.commit().await?;
    Ok(PrincipalMfaStatus {
        required,
        totp_enabled,
    })
}

pub(crate) async fn principal_requires_mfa(
    state: &AppState,
    principal: &PrincipalContext,
) -> Result<bool, ApiError> {
    Ok(principal_mfa_status(state, principal).await?.required)
}

pub(crate) async fn user_has_totp(state: &AppState, user_id: Uuid) -> Result<bool, ApiError> {
    sqlx::query_scalar(
        "select exists (
           select 1 from zeus_private.load_totp_credential($1)
           where confirmed_at is not null
         )",
    )
    .bind(user_id)
    .fetch_one(&state.platform.database)
    .await
    .map_err(Into::into)
}

pub(crate) async fn required_federated_provider(
    state: &AppState,
    principal: &PrincipalContext,
) -> Result<Option<Uuid>, ApiError> {
    let Some(organization_id) = principal.organization_id else {
        return Ok(None);
    };
    let user_id = principal.user_id.ok_or(ApiError::Forbidden)?;
    let mut transaction = crate::database::begin_tenant(
        &state.platform.database,
        TenantScope::organization(Some(user_id), organization_id),
    )
    .await?;
    let provider_id = sqlx::query_scalar::<_, Option<Uuid>>(
        "select required_federated_provider_id
         from organization_identity_policies
         where organization_id = $1 and federated_required",
    )
    .bind(organization_id)
    .fetch_optional(&mut *transaction)
    .await?
    .flatten();
    transaction.commit().await?;
    Ok(provider_id)
}

impl FromRequestParts<AppState> for PrincipalContext {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        if let Some(authorization) = parts.headers.get(header::AUTHORIZATION) {
            let authorization = authorization.to_str().map_err(|_| ApiError::Unauthorized)?;
            let token = authorization
                .strip_prefix("Bearer ")
                .ok_or(ApiError::Unauthorized)?;
            return authenticate_service_account(state, token).await;
        }

        let token = cookie_value(&parts.headers, SESSION_COOKIE).ok_or(ApiError::Unauthorized)?;
        let mut principal = authenticate_user_session(state, token).await?;
        apply_platform_tenant_access_grant(state, &parts.headers, &mut principal).await?;
        Ok(principal)
    }
}

pub async fn enforce_browser_write_security(
    State(state): State<AppState>,
    request: Request<axum::body::Body>,
    next: Next,
) -> Response {
    if matches!(
        *request.method(),
        Method::GET | Method::HEAD | Method::OPTIONS
    ) || request.headers().contains_key(header::AUTHORIZATION)
        || browser_write_security_exempt(request.uri().path())
    {
        return next.run(request).await;
    }
    let Some(session_token) = cookie_value(request.headers(), SESSION_COOKIE) else {
        return next.run(request).await;
    };
    let Some(csrf_cookie) = cookie_value(request.headers(), CSRF_COOKIE) else {
        return ApiError::Forbidden.into_response();
    };
    let Some(csrf_header) = request
        .headers()
        .get(CSRF_HEADER)
        .and_then(|value| value.to_str().ok())
    else {
        return ApiError::Forbidden.into_response();
    };
    if csrf_cookie
        .as_bytes()
        .ct_eq(csrf_header.as_bytes())
        .unwrap_u8()
        != 1
    {
        return ApiError::Forbidden.into_response();
    }
    let expected_origin = state.identity.public_url.origin().ascii_serialization();
    let Some(origin) = request
        .headers()
        .get(header::ORIGIN)
        .and_then(|value| value.to_str().ok())
    else {
        return ApiError::Forbidden.into_response();
    };
    if origin
        .as_bytes()
        .ct_eq(expected_origin.as_bytes())
        .unwrap_u8()
        != 1
    {
        return ApiError::Forbidden.into_response();
    }
    let principal = match authenticate_user_session(&state, session_token).await {
        Ok(principal) => principal,
        Err(error) => return error.into_response(),
    };
    let Some(expected_digest) = principal.csrf_token_hash else {
        return ApiError::Forbidden.into_response();
    };
    let supplied_digest = sha256(csrf_header.as_bytes());
    if expected_digest
        .as_slice()
        .ct_eq(supplied_digest.as_slice())
        .unwrap_u8()
        != 1
    {
        return ApiError::Forbidden.into_response();
    }
    next.run(request).await
}

fn browser_write_security_exempt(path: &str) -> bool {
    matches!(
        path,
        "/api/v1/setup"
            | "/api/v1/auth/login"
            | "/api/v1/auth/register"
            | "/api/v1/auth/email-verifications"
            | "/api/v1/auth/email-verifications/confirm"
            | "/api/v1/auth/password-resets"
            | "/api/v1/auth/password-resets/confirm"
            | "/oauth2/token"
            | "/oauth2/userinfo"
            | "/oauth2/revoke"
    )
}

#[derive(Debug, FromRow)]
struct WebSessionPrincipalRow {
    session_id: Uuid,
    user_id: Uuid,
    active_organization_id: Option<Uuid>,
    active_workspace_id: Option<Uuid>,
    organization_role: Option<String>,
    workspace_role: Option<String>,
    email: String,
    display_name: String,
    email_verified_at: Option<OffsetDateTime>,
    platform_roles: Vec<String>,
    auth_methods: Vec<String>,
    authenticated_at: OffsetDateTime,
    mfa_satisfied_at: Option<OffsetDateTime>,
    idle_expires_at: OffsetDateTime,
    absolute_expires_at: OffsetDateTime,
    csrf_token_hash: Option<Vec<u8>>,
}

#[derive(Debug, FromRow)]
struct PlatformTenantAccessGrantRow {
    grant_id: Uuid,
    organization_id: Uuid,
    organization_status: String,
    reason: String,
    expires_at: OffsetDateTime,
    workspace_id: Option<Uuid>,
}

#[derive(Debug, FromRow)]
struct ServiceAccountPrincipalRow {
    service_account_id: Uuid,
    organization_id: Uuid,
    workspace_id: Option<Uuid>,
    name: String,
    token_hash: String,
    scopes: Vec<String>,
}

async fn authenticate_user_session(
    state: &AppState,
    token: String,
) -> Result<PrincipalContext, ApiError> {
    let digest = sha256(token.as_bytes());
    let row = sqlx::query_as::<_, WebSessionPrincipalRow>(
        "select * from zeus_private.authenticate_user_session($1)",
    )
    .bind(digest)
    .fetch_optional(&state.platform.database)
    .await?
    .ok_or(ApiError::Unauthorized)?;

    Ok(PrincipalContext {
        principal_kind: PrincipalKind::User,
        principal_id: row.user_id,
        user_id: Some(row.user_id),
        session_id: Some(row.session_id),
        tenant_access_grant_id: None,
        tenant_access_reason: None,
        tenant_access_expires_at: None,
        organization_status: None,
        organization_id: row.active_organization_id,
        workspace_id: row.active_workspace_id,
        organization_role: row
            .organization_role
            .as_deref()
            .map(parse_organization_role)
            .transpose()?,
        workspace_role: row
            .workspace_role
            .as_deref()
            .map(parse_workspace_role)
            .transpose()?,
        scopes: BTreeSet::new(),
        email: Some(row.email),
        display_name: row.display_name,
        email_verified_at: row.email_verified_at,
        platform_roles: row.platform_roles.into_iter().collect(),
        auth_methods: row.auth_methods.into_iter().collect(),
        authenticated_at: Some(row.authenticated_at),
        mfa_satisfied_at: row.mfa_satisfied_at,
        idle_expires_at: Some(row.idle_expires_at),
        absolute_expires_at: Some(row.absolute_expires_at),
        csrf_token_hash: row.csrf_token_hash,
    })
}

async fn apply_platform_tenant_access_grant(
    state: &AppState,
    headers: &HeaderMap,
    principal: &mut PrincipalContext,
) -> Result<(), ApiError> {
    if !principal.platform_roles.contains("platform_owner") {
        return Ok(());
    }
    let Some(grant_id) = cookie_value(headers, TENANT_ACCESS_GRANT_COOKIE)
        .and_then(|value| Uuid::parse_str(&value).ok())
    else {
        return Ok(());
    };
    let user_id = principal.user_id.ok_or(ApiError::Forbidden)?;
    let session_id = principal.session_id.ok_or(ApiError::Forbidden)?;
    let Some(grant) = sqlx::query_as::<_, PlatformTenantAccessGrantRow>(
        "select * from zeus_private.validate_platform_tenant_access_grant($1, $2, $3)",
    )
    .bind(grant_id)
    .bind(user_id)
    .bind(session_id)
    .fetch_optional(&state.platform.database)
    .await?
    else {
        return Ok(());
    };
    principal.tenant_access_grant_id = Some(grant.grant_id);
    principal.tenant_access_reason = Some(grant.reason);
    principal.tenant_access_expires_at = Some(grant.expires_at);
    principal.organization_status = Some(grant.organization_status);
    principal.organization_id = Some(grant.organization_id);
    principal.workspace_id = grant.workspace_id;
    principal.organization_role = None;
    principal.workspace_role = None;
    Ok(())
}

async fn load_organization_status(
    state: &AppState,
    principal: &PrincipalContext,
    organization_id: Uuid,
) -> Result<String, ApiError> {
    let mut transaction = begin_tenant(
        &state.platform.database,
        TenantScope {
            user_id: principal.user_id,
            session_id: principal.session_id,
            organization_id,
            workspace_id: principal.workspace_id,
            tenant_access_grant_id: principal.tenant_access_grant_id,
        },
    )
    .await?;
    let status = sqlx::query_scalar::<_, String>("select status from organizations where id = $1")
        .bind(organization_id)
        .fetch_optional(&mut *transaction)
        .await?
        .ok_or(ApiError::NotFound)?;
    transaction.commit().await?;
    Ok(status)
}

pub(crate) async fn authenticate_user_headers(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<PrincipalContext, ApiError> {
    let token = cookie_value(headers, SESSION_COOKIE).ok_or(ApiError::Unauthorized)?;
    authenticate_user_session(state, token).await
}

async fn authenticate_service_account(
    state: &AppState,
    raw_token: &str,
) -> Result<PrincipalContext, ApiError> {
    let (prefix, token) = parse_service_account_token(raw_token)?;
    let row = sqlx::query_as::<_, ServiceAccountPrincipalRow>(
        "select * from zeus_private.lookup_service_account($1)",
    )
    .bind(prefix)
    .fetch_optional(&state.platform.database)
    .await?
    .ok_or(ApiError::Unauthorized)?;

    let verification = state
        .identity
        .password_executor
        .verify(token, row.token_hash.clone())
        .await
        .map_err(|error| map_service_account_password_error(state, error))?;
    if !verification.valid {
        return Err(ApiError::Unauthorized);
    }
    sqlx::query("select zeus_private.touch_service_account($1)")
        .bind(row.service_account_id)
        .execute(&state.platform.database)
        .await?;

    Ok(PrincipalContext {
        principal_kind: PrincipalKind::ServiceAccount,
        principal_id: row.service_account_id,
        user_id: None,
        session_id: None,
        tenant_access_grant_id: None,
        tenant_access_reason: None,
        tenant_access_expires_at: None,
        organization_status: None,
        organization_id: Some(row.organization_id),
        workspace_id: row.workspace_id,
        organization_role: None,
        workspace_role: None,
        scopes: row.scopes.into_iter().collect(),
        email: None,
        display_name: row.name,
        email_verified_at: None,
        platform_roles: BTreeSet::new(),
        auth_methods: BTreeSet::new(),
        authenticated_at: None,
        mfa_satisfied_at: None,
        idle_expires_at: None,
        absolute_expires_at: None,
        csrf_token_hash: None,
    })
}

#[derive(Debug, Deserialize)]
pub struct LoginQuery {
    #[serde(default = "default_return_to")]
    return_to: String,
}

#[derive(Debug, Deserialize)]
pub struct CallbackQuery {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
}

#[derive(Debug, FromRow)]
struct FederatedProviderLoginRow {
    id: Uuid,
    organization_id: Uuid,
    organization_slug: String,
    provider_slug: String,
    issuer_url: String,
    client_id: String,
    encrypted_client_secret: Vec<u8>,
    secret_nonce: Vec<u8>,
    key_id: String,
    scopes: Vec<String>,
    group_claim: Option<String>,
    trusted_acr: Vec<String>,
    trusted_amr: Vec<String>,
}

#[derive(Debug, FromRow)]
struct ConsumedFederatedLoginRow {
    purpose: String,
    initiating_user_id: Option<Uuid>,
    initiating_session_id: Option<Uuid>,
    ciphertext: Vec<u8>,
    nonce: Vec<u8>,
    key_id: String,
}

#[derive(Debug, FromRow)]
#[allow(clippy::struct_field_names)] // Names mirror the SQL function's result columns.
struct ResolvedFederatedIdentityRow {
    disposition: String,
    resolved_user_id: Option<Uuid>,
    resolved_organization_id: Uuid,
    resolved_workspace_id: Option<Uuid>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct ExternalIdentityLinkIntentRequest {
    pub provider_id: Uuid,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ExternalIdentityLinkIntentResponse {
    pub authorization_url: String,
}

pub async fn federated_login(
    State(state): State<AppState>,
    Path((organization_slug, provider_slug)): Path<(String, String)>,
    Query(query): Query<LoginQuery>,
) -> Result<Response, ApiError> {
    let provider = load_federated_provider(&state, &organization_slug, &provider_slug).await?;
    let authorization_url =
        begin_federated_authorization(&state, &provider, "login", None, None, query.return_to)
            .await?;
    redirect_response(authorization_url.as_str(), &[])
}

#[utoipa::path(
    post,
    path = "/api/v1/users/me/external-identities/link-intents",
    tag = "identity",
    request_body = ExternalIdentityLinkIntentRequest,
    responses((status = 200, description = "External identity link authorization URL", body = ExternalIdentityLinkIntentResponse))
)]
pub async fn create_external_identity_link_intent(
    State(state): State<AppState>,
    principal: PrincipalContext,
    Json(request): Json<ExternalIdentityLinkIntentRequest>,
) -> Result<Json<ExternalIdentityLinkIntentResponse>, ApiError> {
    if principal.email_verified_at.is_none() {
        return Err(ApiError::EmailVerificationRequired);
    }
    crate::native_auth::require_recent_authentication(&principal)?;
    let user_id = principal.user_id.ok_or(ApiError::Forbidden)?;
    let session_id = principal.session_id.ok_or(ApiError::Forbidden)?;
    let provider = sqlx::query_as::<_, FederatedProviderLoginRow>(
        "select * from zeus_private.get_federated_provider_for_link($1, $2, $3)",
    )
    .bind(request.provider_id)
    .bind(user_id)
    .bind(session_id)
    .fetch_optional(&state.platform.database)
    .await?
    .ok_or(ApiError::NotFound)?;
    let authorization_url = begin_federated_authorization(
        &state,
        &provider,
        "link",
        Some(user_id),
        Some(session_id),
        "/account/federation".to_owned(),
    )
    .await?;
    Ok(Json(ExternalIdentityLinkIntentResponse {
        authorization_url: authorization_url.into(),
    }))
}

#[allow(clippy::too_many_lines)] // The callback keeps protocol checks in their execution order.
pub async fn federated_callback(
    State(state): State<AppState>,
    Path((organization_slug, provider_slug)): Path<(String, String)>,
    Query(query): Query<CallbackQuery>,
) -> Result<Response, ApiError> {
    if query.error.is_some() {
        return Err(ApiError::Unauthorized);
    }
    let state_value = query
        .state
        .ok_or_else(|| ApiError::BadRequest("missing state".to_owned()))?;
    let code = query
        .code
        .ok_or_else(|| ApiError::BadRequest("missing code".to_owned()))?;
    let provider = load_federated_provider(&state, &organization_slug, &provider_slug).await?;
    let consumed = sqlx::query_as::<_, ConsumedFederatedLoginRow>(
        "select * from zeus_private.consume_federated_login_transaction($1, $2)",
    )
    .bind(provider.id)
    .bind(sha256(state_value.as_bytes()))
    .fetch_optional(&state.platform.database)
    .await?
    .ok_or(ApiError::Unauthorized)?;
    let aad = federated_login_aad(provider.id);
    let plaintext = state
        .platform
        .envelope
        .open(
            &SealedSecret {
                ciphertext: consumed.ciphertext,
                nonce: consumed.nonce,
                key_id: consumed.key_id,
            },
            aad.as_bytes(),
        )
        .map_err(|_| ApiError::Unauthorized)?;
    let pending: PendingOidcAuthorization =
        serde_json::from_slice(&plaintext).map_err(|_| ApiError::Unauthorized)?;
    if sha256(pending.state.as_bytes()) != sha256(state_value.as_bytes()) {
        return Err(ApiError::Unauthorized);
    }

    let redirect_url = federated_callback_url(&state, &provider)?;
    let identity = OidcFlow::new(
        &state.external.http,
        state.identity.allow_private_oidc_issuers,
    )
    .complete(
        &provider_config(&state, &provider)?,
        redirect_url,
        code,
        &pending,
    )
    .await
    .map_err(|_| {
        state.platform.metrics.record_federated_provider_error();
        ApiError::IdentityProvider
    })?;
    let resolved = sqlx::query_as::<_, ResolvedFederatedIdentityRow>(
        "select * from zeus_private.resolve_external_identity(
           $1, $2, $3, $4, $5, $6, $7, $8, $9, $10
         )",
    )
    .bind(provider.id)
    .bind(&consumed.purpose)
    .bind(consumed.initiating_user_id)
    .bind(&identity.issuer)
    .bind(&identity.subject)
    .bind(identity.email.to_ascii_lowercase())
    .bind(&identity.display_name)
    .bind(identity.email_verified)
    .bind(&identity.stored_claims)
    .bind(&identity.groups)
    .fetch_one(&state.platform.database)
    .await?;
    if resolved.resolved_organization_id != provider.organization_id {
        return Err(ApiError::Unauthorized);
    }

    if resolved.disposition == "account_link_required" {
        return redirect_response("/login?error=account_link_required", &[]);
    }
    if resolved.disposition == "jit_not_allowed" {
        return redirect_response("/login?error=federated_not_allowed", &[]);
    }
    let user_id = resolved.resolved_user_id.ok_or(ApiError::Unauthorized)?;
    let method = format!("federated:{}", provider.id);
    let mfa_satisfied_at =
        trusted_federated_mfa(&provider, &identity).then(OffsetDateTime::now_utc);

    if consumed.purpose == "link" {
        if consumed.initiating_user_id != Some(user_id) {
            return Err(ApiError::Unauthorized);
        }
        let session_id = consumed
            .initiating_session_id
            .ok_or(ApiError::Unauthorized)?;
        let cookies =
            rotate_federated_session(&state, session_id, user_id, mfa_satisfied_at, &method)
                .await?;
        return redirect_response("/account/federation?linked=1", &cookies);
    }

    let session_token = random_token(32).map_err(|_| ApiError::Internal)?;
    let csrf_token = random_token(32).map_err(|_| ApiError::Internal)?;
    sqlx::query_scalar::<_, Uuid>(
        "select zeus_private.create_user_session($1, $2, $3, $4, $5, $6, $7, $8, $9)",
    )
    .bind(user_id)
    .bind(resolved.resolved_organization_id)
    .bind(resolved.resolved_workspace_id)
    .bind(sha256(session_token.expose_secret().as_bytes()))
    .bind(sha256(csrf_token.expose_secret().as_bytes()))
    .bind(vec![method])
    .bind(mfa_satisfied_at)
    .bind(i32::try_from(state.identity.session_idle_ttl.as_secs()).unwrap_or(i32::MAX))
    .bind(i32::try_from(state.identity.session_absolute_ttl.as_secs()).unwrap_or(i32::MAX))
    .fetch_one(&state.platform.database)
    .await?;

    let redirect_to = if mfa_satisfied_at.is_none() {
        let principal =
            authenticate_user_session(&state, session_token.expose_secret().to_owned()).await?;
        if principal_requires_mfa(&state, &principal).await? {
            if user_has_totp(&state, user_id).await? {
                "/mfa".to_owned()
            } else {
                "/account/security?setup_totp=1".to_owned()
            }
        } else {
            sanitize_return_to(&pending.return_to)
        }
    } else {
        sanitize_return_to(&pending.return_to)
    };

    let cookies = vec![
        session_cookie(
            &state,
            session_token.expose_secret(),
            state.identity.session_absolute_ttl.as_secs(),
        ),
        csrf_cookie(
            &state,
            csrf_token.expose_secret(),
            state.identity.session_absolute_ttl.as_secs(),
        ),
    ];
    redirect_response(&redirect_to, &cookies)
}

pub async fn logout(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    if let Some(token) = cookie_value(&headers, SESSION_COOKIE) {
        sqlx::query("select zeus_private.revoke_web_session($1)")
            .bind(sha256(token.as_bytes()))
            .execute(&state.platform.database)
            .await?;
    }
    let cookies = vec![
        expired_session_cookie(&state),
        expired_csrf_cookie(&state),
        expired_tenant_access_grant_cookie(&state),
    ];
    redirect_response("/", &cookies)
}

#[derive(Debug, Serialize, ToSchema)]
pub struct CurrentUserResponse {
    pub principal_kind: String,
    pub principal_id: Uuid,
    pub user_id: Option<Uuid>,
    pub tenant_access_grant_id: Option<Uuid>,
    #[serde(with = "time::serde::rfc3339::option")]
    pub tenant_access_expires_at: Option<OffsetDateTime>,
    pub organization_id: Option<Uuid>,
    pub workspace_id: Option<Uuid>,
    pub organization_role: Option<String>,
    pub workspace_role: Option<String>,
    pub scopes: Vec<String>,
    pub email: Option<String>,
    pub display_name: String,
    #[serde(with = "time::serde::rfc3339::option")]
    pub email_verified_at: Option<OffsetDateTime>,
    pub platform_roles: Vec<String>,
    pub auth_methods: Vec<String>,
    pub has_native_password: bool,
    pub totp_enabled: bool,
    pub mfa_required: bool,
    #[serde(with = "time::serde::rfc3339::option")]
    pub authenticated_at: Option<OffsetDateTime>,
    #[serde(with = "time::serde::rfc3339::option")]
    pub mfa_satisfied_at: Option<OffsetDateTime>,
    #[serde(with = "time::serde::rfc3339::option")]
    pub idle_expires_at: Option<OffsetDateTime>,
    #[serde(with = "time::serde::rfc3339::option")]
    pub absolute_expires_at: Option<OffsetDateTime>,
}

#[utoipa::path(get, path = "/api/v1/auth/me", tag = "identity", responses(
    (status = 200, description = "Current authenticated principal", body = CurrentUserResponse),
    (status = 401, description = "Authentication required", body = crate::error::ProblemDetails, content_type = "application/problem+json")
))]
pub async fn current_user(
    State(state): State<AppState>,
    auth: PrincipalContext,
) -> Result<Json<CurrentUserResponse>, ApiError> {
    let mfa_status = if auth.principal_kind == PrincipalKind::User {
        principal_mfa_status(&state, &auth).await?
    } else {
        PrincipalMfaStatus::default()
    };
    let has_native_password = match (auth.user_id, auth.session_id) {
        (Some(user_id), Some(session_id)) => {
            sqlx::query_scalar("select zeus_private.user_has_native_password($1, $2)")
                .bind(user_id)
                .bind(session_id)
                .fetch_one(&state.platform.database)
                .await?
        }
        _ => false,
    };
    Ok(Json(CurrentUserResponse {
        principal_kind: match auth.principal_kind {
            PrincipalKind::User => "user",
            PrincipalKind::ServiceAccount => "service_account",
        }
        .to_owned(),
        principal_id: auth.principal_id,
        user_id: auth.user_id,
        tenant_access_grant_id: auth.tenant_access_grant_id,
        tenant_access_expires_at: auth.tenant_access_expires_at,
        organization_id: auth.organization_id,
        workspace_id: auth.workspace_id,
        organization_role: auth.organization_role.map(organization_role_name),
        workspace_role: auth.workspace_role.map(workspace_role_name),
        scopes: auth.scopes.into_iter().collect(),
        email: auth.email,
        display_name: auth.display_name,
        email_verified_at: auth.email_verified_at,
        platform_roles: auth.platform_roles.into_iter().collect(),
        auth_methods: auth.auth_methods.into_iter().collect(),
        has_native_password,
        totp_enabled: mfa_status.totp_enabled,
        mfa_required: mfa_status.required,
        authenticated_at: auth.authenticated_at,
        mfa_satisfied_at: auth.mfa_satisfied_at,
        idle_expires_at: auth.idle_expires_at,
        absolute_expires_at: auth.absolute_expires_at,
    }))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateServiceAccountRequest {
    pub name: String,
    pub workspace_id: Option<Uuid>,
    #[serde(default)]
    pub scopes: Vec<String>,
    #[serde(with = "time::serde::rfc3339::option")]
    pub expires_at: Option<OffsetDateTime>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateWorkspaceServiceAccountRequest {
    pub name: String,
    #[serde(default)]
    pub scopes: Vec<String>,
    #[serde(with = "time::serde::rfc3339::option")]
    pub expires_at: Option<OffsetDateTime>,
}

#[derive(Serialize, ToSchema)]
pub struct CreatedServiceAccountResponse {
    pub id: Uuid,
    pub organization_id: Uuid,
    pub workspace_id: Option<Uuid>,
    pub name: String,
    pub token_prefix: String,
    #[schema(value_type = String, example = "zsa_REDACTED.REDACTED")]
    pub token: String,
    pub scopes: Vec<String>,
    #[serde(with = "time::serde::rfc3339::option")]
    pub expires_at: Option<OffsetDateTime>,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

#[derive(Debug, FromRow)]
struct CreatedServiceAccountRow {
    id: Uuid,
    created_at: OffsetDateTime,
}

#[utoipa::path(post, path = "/api/v1/organizations/{organization_id}/service-accounts", tag = "identity",
    params(("organization_id" = Uuid, Path)),
    request_body = CreateServiceAccountRequest,
    responses((status = 201, description = "Service account and one-time token", body = CreatedServiceAccountResponse))
)]
pub async fn create_service_account(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(organization_id): Path<Uuid>,
    Json(request): Json<CreateServiceAccountRequest>,
) -> Result<(StatusCode, Json<CreatedServiceAccountResponse>), ApiError> {
    if let Some(workspace_id) = request.workspace_id {
        if auth.organization_id != organization_id {
            return Err(ApiError::Forbidden);
        }
        auth.require_workspace(workspace_id, Permission::ManageWorkspace)?;
    } else {
        auth.require_organization(organization_id, Permission::ManageOrganization)?;
    }
    auth.require_recent_authentication()?;
    validate_service_account_request(&request)?;

    create_service_account_record(state, auth, organization_id, request).await
}

#[utoipa::path(post, path = "/api/v1/workspaces/{workspace_id}/service-accounts", tag = "identity",
    params(("workspace_id" = Uuid, Path)),
    request_body = CreateWorkspaceServiceAccountRequest,
    responses((status = 201, description = "Workspace service account and one-time token", body = CreatedServiceAccountResponse))
)]
pub async fn create_workspace_service_account(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(workspace_id): Path<Uuid>,
    Json(request): Json<CreateWorkspaceServiceAccountRequest>,
) -> Result<(StatusCode, Json<CreatedServiceAccountResponse>), ApiError> {
    auth.require_workspace(workspace_id, Permission::ManageWorkspace)?;
    auth.require_recent_authentication()?;
    let organization_id = auth.organization_id;
    let request = CreateServiceAccountRequest {
        name: request.name,
        workspace_id: Some(workspace_id),
        scopes: request.scopes,
        expires_at: request.expires_at,
    };
    validate_service_account_request(&request)?;

    create_service_account_record(state, auth, organization_id, request).await
}

async fn create_service_account_record(
    state: AppState,
    auth: AuthContext,
    organization_id: Uuid,
    request: CreateServiceAccountRequest,
) -> Result<(StatusCode, Json<CreatedServiceAccountResponse>), ApiError> {
    let prefix_secret = random_token(9).map_err(|_| ApiError::Internal)?;
    let token_secret = random_token(32).map_err(|_| ApiError::Internal)?;
    let token_prefix = format!("{SERVICE_ACCOUNT_PREFIX}{}", prefix_secret.expose_secret());
    let full_token = SecretString::from(format!("{token_prefix}.{}", token_secret.expose_secret()));
    let token_hash = state
        .identity
        .password_executor
        .hash(full_token.clone())
        .await
        .map_err(|error| map_service_account_password_error(&state, error))?;

    let mut transaction = begin_tenant(
        &state.platform.database,
        auth.tenant_scope(request.workspace_id),
    )
    .await?;
    let created = sqlx::query_as::<_, CreatedServiceAccountRow>(
        "insert into service_accounts (
            organization_id, workspace_id, name, token_prefix, token_hash, scopes, expires_at
         ) values ($1, $2, $3, $4, $5, $6, $7)
         returning id, created_at",
    )
    .bind(organization_id)
    .bind(request.workspace_id)
    .bind(request.name.trim())
    .bind(&token_prefix)
    .bind(token_hash)
    .bind(&request.scopes)
    .bind(request.expires_at)
    .fetch_one(&mut *transaction)
    .await?;
    insert_audit(
        &mut transaction,
        &auth,
        request.workspace_id,
        "service_account.created",
        "service_account",
        created.id,
    )
    .await?;
    transaction.commit().await?;

    Ok((
        StatusCode::CREATED,
        Json(CreatedServiceAccountResponse {
            id: created.id,
            organization_id,
            workspace_id: request.workspace_id,
            name: request.name.trim().to_owned(),
            token_prefix,
            token: full_token.expose_secret().to_owned(),
            scopes: request.scopes,
            expires_at: request.expires_at,
            created_at: created.created_at,
        }),
    ))
}

#[derive(Debug, Serialize, ToSchema, FromRow)]
pub struct ServiceAccountResponse {
    pub id: Uuid,
    pub organization_id: Uuid,
    pub workspace_id: Option<Uuid>,
    pub name: String,
    pub token_prefix: String,
    pub scopes: Vec<String>,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339::option")]
    pub expires_at: Option<OffsetDateTime>,
    #[serde(with = "time::serde::rfc3339::option")]
    pub revoked_at: Option<OffsetDateTime>,
    #[serde(with = "time::serde::rfc3339::option")]
    pub last_used_at: Option<OffsetDateTime>,
}

#[utoipa::path(get, path = "/api/v1/organizations/{organization_id}/service-accounts", tag = "identity",
    params(("organization_id" = Uuid, Path)),
    responses((status = 200, description = "Service accounts without token hashes", body = [ServiceAccountResponse]))
)]
pub async fn list_service_accounts(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(organization_id): Path<Uuid>,
) -> Result<Json<Vec<ServiceAccountResponse>>, ApiError> {
    auth.require_organization(organization_id, Permission::ManageOrganization)?;
    let mut transaction = begin_tenant(&state.platform.database, auth.tenant_scope(None)).await?;
    let accounts = sqlx::query_as::<_, ServiceAccountResponse>(
        "select id, organization_id, workspace_id, name, token_prefix, scopes,
                created_at, expires_at, revoked_at, last_used_at
         from service_accounts
         where organization_id = $1
         order by created_at desc, id desc
         limit 200",
    )
    .bind(organization_id)
    .fetch_all(&mut *transaction)
    .await?;
    transaction.commit().await?;
    Ok(Json(accounts))
}

#[utoipa::path(get, path = "/api/v1/workspaces/{workspace_id}/service-accounts", tag = "identity",
    params(("workspace_id" = Uuid, Path)),
    responses((status = 200, description = "Workspace service accounts without token hashes", body = [ServiceAccountResponse]))
)]
pub async fn list_workspace_service_accounts(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(workspace_id): Path<Uuid>,
) -> Result<Json<Vec<ServiceAccountResponse>>, ApiError> {
    auth.require_workspace(workspace_id, Permission::ManageWorkspace)?;
    let mut transaction = begin_tenant(
        &state.platform.database,
        auth.tenant_scope(Some(workspace_id)),
    )
    .await?;
    let accounts = sqlx::query_as::<_, ServiceAccountResponse>(
        "select id, organization_id, workspace_id, name, token_prefix, scopes,
                created_at, expires_at, revoked_at, last_used_at
         from service_accounts
         where organization_id = $1 and workspace_id = $2
         order by created_at desc, id desc
         limit 200",
    )
    .bind(auth.organization_id)
    .bind(workspace_id)
    .fetch_all(&mut *transaction)
    .await?;
    transaction.commit().await?;
    Ok(Json(accounts))
}

#[utoipa::path(post, path = "/api/v1/organizations/{organization_id}/service-accounts/{service_account_id}/revoke", tag = "identity",
    params(("organization_id" = Uuid, Path), ("service_account_id" = Uuid, Path)),
    responses((status = 204, description = "Service account revoked"))
)]
pub async fn revoke_service_account(
    State(state): State<AppState>,
    auth: AuthContext,
    Path((organization_id, service_account_id)): Path<(Uuid, Uuid)>,
) -> Result<StatusCode, ApiError> {
    auth.require_organization(organization_id, Permission::ManageOrganization)?;
    let mut transaction = begin_tenant(&state.platform.database, auth.tenant_scope(None)).await?;
    let result = sqlx::query(
        "update service_accounts set revoked_at = coalesce(revoked_at, now())
         where id = $1 and organization_id = $2",
    )
    .bind(service_account_id)
    .bind(organization_id)
    .execute(&mut *transaction)
    .await?;
    if result.rows_affected() != 1 {
        return Err(ApiError::NotFound);
    }
    insert_audit(
        &mut transaction,
        &auth,
        None,
        "service_account.revoked",
        "service_account",
        service_account_id,
    )
    .await?;
    transaction.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(post, path = "/api/v1/workspaces/{workspace_id}/service-accounts/{service_account_id}/revoke", tag = "identity",
    params(("workspace_id" = Uuid, Path), ("service_account_id" = Uuid, Path)),
    responses((status = 204, description = "Workspace service account revoked"))
)]
pub async fn revoke_workspace_service_account(
    State(state): State<AppState>,
    auth: AuthContext,
    Path((workspace_id, service_account_id)): Path<(Uuid, Uuid)>,
) -> Result<StatusCode, ApiError> {
    auth.require_workspace(workspace_id, Permission::ManageWorkspace)?;
    let mut transaction = begin_tenant(
        &state.platform.database,
        auth.tenant_scope(Some(workspace_id)),
    )
    .await?;
    let result = sqlx::query(
        "update service_accounts set revoked_at = coalesce(revoked_at, now())
         where id = $1 and organization_id = $2 and workspace_id = $3",
    )
    .bind(service_account_id)
    .bind(auth.organization_id)
    .bind(workspace_id)
    .execute(&mut *transaction)
    .await?;
    if result.rows_affected() != 1 {
        return Err(ApiError::NotFound);
    }
    insert_audit(
        &mut transaction,
        &auth,
        Some(workspace_id),
        "service_account.revoked",
        "service_account",
        service_account_id,
    )
    .await?;
    transaction.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

pub fn routes() -> Router<AppState> {
    Router::new()
        .route(
            "/auth/federated/{organization_slug}/{provider_slug}",
            get(federated_login),
        )
        .route(
            "/auth/federated/{organization_slug}/{provider_slug}/callback",
            get(federated_callback),
        )
        .route("/auth/logout", post(logout))
        .route("/api/v1/auth/me", get(current_user))
        .route(
            "/api/v1/users/me/external-identities/link-intents",
            post(create_external_identity_link_intent),
        )
        .route(
            "/api/v1/organizations/{organization_id}/service-accounts",
            get(list_service_accounts).post(create_service_account),
        )
        .route(
            "/api/v1/organizations/{organization_id}/service-accounts/{service_account_id}/revoke",
            post(revoke_service_account),
        )
        .route(
            "/api/v1/workspaces/{workspace_id}/service-accounts",
            get(list_workspace_service_accounts).post(create_workspace_service_account),
        )
        .route(
            "/api/v1/workspaces/{workspace_id}/service-accounts/{service_account_id}/revoke",
            post(revoke_workspace_service_account),
        )
}

fn provider_config(
    state: &AppState,
    row: &FederatedProviderLoginRow,
) -> Result<OidcProviderConfig, ApiError> {
    let aad = format!("oidc-provider/{}/client-secret", row.id);
    let plaintext = state
        .platform
        .envelope
        .open(
            &SealedSecret {
                ciphertext: row.encrypted_client_secret.clone(),
                nonce: row.secret_nonce.clone(),
                key_id: row.key_id.clone(),
            },
            aad.as_bytes(),
        )
        .map_err(|_| ApiError::Internal)?;
    let client_secret = String::from_utf8(plaintext).map_err(|_| ApiError::Internal)?;
    Ok(OidcProviderConfig {
        issuer_url: url::Url::parse(&row.issuer_url).map_err(|_| ApiError::Internal)?,
        client_id: row.client_id.clone(),
        client_secret: SecretString::from(client_secret),
        scopes: row.scopes.clone(),
        group_claim: row.group_claim.clone(),
    })
}

async fn load_federated_provider(
    state: &AppState,
    organization_slug: &str,
    provider_slug: &str,
) -> Result<FederatedProviderLoginRow, ApiError> {
    sqlx::query_as::<_, FederatedProviderLoginRow>(
        "select * from zeus_private.get_federated_provider_for_login($1, $2)",
    )
    .bind(organization_slug)
    .bind(provider_slug)
    .fetch_optional(&state.platform.database)
    .await?
    .ok_or(ApiError::NotFound)
}

fn federated_callback_url(
    state: &AppState,
    provider: &FederatedProviderLoginRow,
) -> Result<url::Url, ApiError> {
    state
        .identity
        .public_url
        .join(&format!(
            "auth/federated/{}/{}/callback",
            provider.organization_slug, provider.provider_slug
        ))
        .map_err(|_| ApiError::Internal)
}

fn federated_login_aad(provider_id: Uuid) -> String {
    format!("federated-login/{provider_id}")
}

async fn begin_federated_authorization(
    state: &AppState,
    provider: &FederatedProviderLoginRow,
    purpose: &str,
    initiating_user_id: Option<Uuid>,
    initiating_session_id: Option<Uuid>,
    return_to: String,
) -> Result<url::Url, ApiError> {
    let redirect_url = federated_callback_url(state, provider)?;
    let authorization = OidcFlow::new(
        &state.external.http,
        state.identity.allow_private_oidc_issuers,
    )
    .authorize(
        &provider_config(state, provider)?,
        redirect_url.clone(),
        return_to,
    )
    .await
    .map_err(|_| {
        state.platform.metrics.record_federated_provider_error();
        ApiError::IdentityProvider
    })?;
    let pending_json =
        serde_json::to_vec(&authorization.pending).map_err(|_| ApiError::Internal)?;
    let aad = federated_login_aad(provider.id);
    let sealed = state
        .platform
        .envelope
        .seal(&pending_json, aad.as_bytes())
        .map_err(|_| ApiError::Internal)?;
    sqlx::query_scalar::<_, Uuid>(
        "select zeus_private.create_federated_login_transaction(
           $1, $2, $3, $4, $5, $6, $7, $8, $9, $10
         )",
    )
    .bind(provider.id)
    .bind(purpose)
    .bind(initiating_user_id)
    .bind(initiating_session_id)
    .bind(sha256(authorization.pending.state.as_bytes()))
    .bind(sealed.ciphertext)
    .bind(sealed.nonce)
    .bind(sealed.key_id)
    .bind(redirect_url.to_string())
    .bind(
        OffsetDateTime::now_utc()
            + time::Duration::seconds(
                i64::try_from(state.identity.oidc_state_ttl.as_secs()).unwrap_or(i64::MAX),
            ),
    )
    .fetch_one(&state.platform.database)
    .await?;
    Ok(authorization.url)
}

fn trusted_federated_mfa(
    provider: &FederatedProviderLoginRow,
    identity: &VerifiedOidcIdentity,
) -> bool {
    identity
        .acr
        .as_ref()
        .is_some_and(|acr| provider.trusted_acr.contains(acr))
        || identity
            .amr
            .iter()
            .any(|amr| provider.trusted_amr.contains(amr))
}

async fn rotate_federated_session(
    state: &AppState,
    session_id: Uuid,
    user_id: Uuid,
    mfa_satisfied_at: Option<OffsetDateTime>,
    method: &str,
) -> Result<Vec<String>, ApiError> {
    let session_token = random_token(32).map_err(|_| ApiError::Internal)?;
    let csrf_token = random_token(32).map_err(|_| ApiError::Internal)?;
    let rotated: bool =
        sqlx::query_scalar("select zeus_private.rotate_user_session_token($1, $2, $3, $4, $5, $6)")
            .bind(session_id)
            .bind(user_id)
            .bind(sha256(session_token.expose_secret().as_bytes()))
            .bind(sha256(csrf_token.expose_secret().as_bytes()))
            .bind(mfa_satisfied_at)
            .bind(method)
            .fetch_one(&state.platform.database)
            .await?;
    if !rotated {
        return Err(ApiError::Unauthorized);
    }
    Ok(vec![
        session_cookie(
            state,
            session_token.expose_secret(),
            state.identity.session_absolute_ttl.as_secs(),
        ),
        csrf_cookie(
            state,
            csrf_token.expose_secret(),
            state.identity.session_absolute_ttl.as_secs(),
        ),
    ])
}

pub(crate) fn session_cookie(state: &AppState, token: &str, max_age_seconds: u64) -> String {
    let secure = if state.identity.cookie_secure {
        "; Secure"
    } else {
        ""
    };
    format!(
        "{SESSION_COOKIE}={token}; Path=/; HttpOnly; SameSite=Lax; Max-Age={max_age_seconds}{secure}"
    )
}

pub(crate) fn expired_session_cookie(state: &AppState) -> String {
    let secure = if state.identity.cookie_secure {
        "; Secure"
    } else {
        ""
    };
    format!("{SESSION_COOKIE}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0{secure}")
}

pub(crate) fn csrf_cookie(state: &AppState, token: &str, max_age_seconds: u64) -> String {
    let secure = if state.identity.cookie_secure {
        "; Secure"
    } else {
        ""
    };
    format!("{CSRF_COOKIE}={token}; Path=/; SameSite=Lax; Max-Age={max_age_seconds}{secure}")
}

pub(crate) fn expired_csrf_cookie(state: &AppState) -> String {
    let secure = if state.identity.cookie_secure {
        "; Secure"
    } else {
        ""
    };
    format!("{CSRF_COOKIE}=; Path=/; SameSite=Lax; Max-Age=0{secure}")
}

pub(crate) fn tenant_access_grant_cookie(
    state: &AppState,
    grant_id: Uuid,
    max_age_seconds: u64,
) -> String {
    let secure = if state.identity.cookie_secure {
        "; Secure"
    } else {
        ""
    };
    format!(
        "{TENANT_ACCESS_GRANT_COOKIE}={grant_id}; Path=/; HttpOnly; SameSite=Lax; Max-Age={max_age_seconds}{secure}"
    )
}

pub(crate) fn expired_tenant_access_grant_cookie(state: &AppState) -> String {
    let secure = if state.identity.cookie_secure {
        "; Secure"
    } else {
        ""
    };
    format!("{TENANT_ACCESS_GRANT_COOKIE}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0{secure}")
}

fn redirect_response(location: &str, cookies: &[String]) -> Result<Response, ApiError> {
    let mut response = StatusCode::SEE_OTHER.into_response();
    response.headers_mut().insert(
        header::LOCATION,
        HeaderValue::from_str(location)
            .map_err(|_| ApiError::BadRequest("invalid redirect".to_owned()))?,
    );
    for cookie in cookies {
        response.headers_mut().append(
            header::SET_COOKIE,
            HeaderValue::from_str(cookie).map_err(|_| ApiError::Internal)?,
        );
    }
    Ok(response)
}

fn cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(';'))
        .filter_map(|part| part.trim().split_once('='))
        .find_map(|(cookie_name, value)| (cookie_name == name).then(|| value.to_owned()))
}

fn parse_service_account_token(raw: &str) -> Result<(String, SecretString), ApiError> {
    let (prefix, secret) = raw.split_once('.').ok_or(ApiError::Unauthorized)?;
    if !prefix.starts_with(SERVICE_ACCOUNT_PREFIX)
        || prefix.len() < SERVICE_ACCOUNT_PREFIX.len() + 8
        || secret.len() < 32
    {
        return Err(ApiError::Unauthorized);
    }
    Ok((prefix.to_owned(), SecretString::from(raw.to_owned())))
}

fn validate_service_account_request(request: &CreateServiceAccountRequest) -> Result<(), ApiError> {
    if request.name.trim().is_empty() || request.name.len() > 120 {
        return Err(ApiError::Validation(
            "name must contain between 1 and 120 characters".to_owned(),
        ));
    }
    if request.scopes.is_empty()
        || request
            .scopes
            .iter()
            .any(|scope| !KNOWN_SERVICE_ACCOUNT_SCOPES.contains(&scope.as_str()))
    {
        return Err(ApiError::Validation(
            "service account scopes contain an unknown or empty value".to_owned(),
        ));
    }
    if request.workspace_id.is_some()
        && request
            .scopes
            .iter()
            .any(|scope| scope == "organization:manage")
    {
        return Err(ApiError::Validation(
            "workspace service accounts cannot receive organization scopes".to_owned(),
        ));
    }
    if request
        .expires_at
        .is_some_and(|expires| expires <= OffsetDateTime::now_utc())
    {
        return Err(ApiError::Validation(
            "expires_at must be in the future".to_owned(),
        ));
    }
    Ok(())
}

fn map_service_account_password_error(state: &AppState, error: PasswordExecutorError) -> ApiError {
    match error {
        PasswordExecutorError::QueueFull => {
            state.platform.metrics.record_identity_throttled();
            ApiError::RateLimited(1)
        }
        PasswordExecutorError::InvalidQueueCapacity
        | PasswordExecutorError::InvalidConcurrency
        | PasswordExecutorError::Password(_)
        | PasswordExecutorError::TaskFailed
        | PasswordExecutorError::ExecutorClosed => ApiError::Internal,
    }
}

pub(crate) async fn insert_audit(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    auth: &AuthContext,
    workspace_id: Option<Uuid>,
    action: &str,
    target_type: &str,
    target_id: Uuid,
) -> Result<(), ApiError> {
    sqlx::query(
        "insert into audit_events (
            organization_id, workspace_id, actor_kind, actor_id, action, target_type, target_id,
            metadata
         ) values ($1, $2, $3, $4, $5, $6, $7, $8)",
    )
    .bind(auth.organization_id)
    .bind(workspace_id)
    .bind(match auth.principal_kind {
        PrincipalKind::User => "user",
        PrincipalKind::ServiceAccount => "service_account",
    })
    .bind(auth.principal_id)
    .bind(action)
    .bind(target_type)
    .bind(target_id)
    .bind(
        match (
            auth.tenant_access_grant_id,
            auth.tenant_access_reason.as_deref(),
        ) {
            (Some(grant_id), Some(reason)) => serde_json::json!({
                "platform_tenant_access_grant_id": grant_id,
                "platform_tenant_access_reason": reason,
            }),
            _ => serde_json::json!({}),
        },
    )
    .execute(&mut **transaction)
    .await?;
    if let (Some(grant_id), Some(session_id), Some(reason)) = (
        auth.tenant_access_grant_id,
        auth.session_id,
        auth.tenant_access_reason.as_deref(),
    ) {
        let recorded: bool = sqlx::query_scalar(
            "select zeus_private.record_platform_support_operation(
               $1, $2, $3, $4, $5, $6, $7, $8, $9
             )",
        )
        .bind(auth.user_id.ok_or(ApiError::Forbidden)?)
        .bind(session_id)
        .bind(grant_id)
        .bind(auth.organization_id)
        .bind(workspace_id)
        .bind(action)
        .bind(target_type)
        .bind(target_id)
        .bind(reason)
        .fetch_one(&mut **transaction)
        .await?;
        if !recorded {
            return Err(ApiError::PlatformTenantAccessRequired);
        }
    }
    Ok(())
}

fn parse_organization_role(value: &str) -> Result<OrganizationRole, ApiError> {
    match value {
        "owner" => Ok(OrganizationRole::Owner),
        "member" => Ok(OrganizationRole::Member),
        "auditor" => Ok(OrganizationRole::Auditor),
        _ => Err(ApiError::Internal),
    }
}

fn parse_workspace_role(value: &str) -> Result<WorkspaceRole, ApiError> {
    match value {
        "owner" => Ok(WorkspaceRole::Owner),
        "builder" => Ok(WorkspaceRole::Builder),
        "operator" => Ok(WorkspaceRole::Operator),
        "viewer" => Ok(WorkspaceRole::Viewer),
        _ => Err(ApiError::Internal),
    }
}

fn organization_role_name(role: OrganizationRole) -> String {
    match role {
        OrganizationRole::Owner => "owner",
        OrganizationRole::Member => "member",
        OrganizationRole::Auditor => "auditor",
    }
    .to_owned()
}

fn workspace_role_name(role: WorkspaceRole) -> String {
    match role {
        WorkspaceRole::Owner => "owner",
        WorkspaceRole::Builder => "builder",
        WorkspaceRole::Operator => "operator",
        WorkspaceRole::Viewer => "viewer",
    }
    .to_owned()
}

fn default_return_to() -> String {
    "/".to_owned()
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use axum::http::{HeaderMap, HeaderValue, header};
    use time::OffsetDateTime;
    use uuid::Uuid;
    use zeus_core::{OrganizationRole, Permission, WorkspaceRole};

    use crate::error::ApiError;

    use super::{
        AuthContext, CreateServiceAccountRequest, CurrentUserResponse, PrincipalKind,
        SESSION_COOKIE, browser_write_security_exempt, cookie_value, parse_service_account_token,
        validate_service_account_request,
    };

    #[test]
    fn cookie_parser_does_not_confuse_neighboring_names() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            HeaderValue::from_static("other=x; zeus_session=expected; zeus_session_old=no"),
        );
        assert_eq!(
            cookie_value(&headers, SESSION_COOKIE).as_deref(),
            Some("expected")
        );
    }

    #[test]
    fn service_account_token_requires_prefix_and_secret() {
        assert!(
            parse_service_account_token("zsa_12345678.abcdefghijklmnopqrstuvwxyz123456").is_ok()
        );
        assert!(parse_service_account_token("wrong.abcdefghijklmnopqrstuvwxyz123456").is_err());
    }

    #[test]
    fn workspace_service_account_rejects_organization_scope() {
        let request = CreateServiceAccountRequest {
            name: "workspace automation".to_owned(),
            workspace_id: Some(Uuid::now_v7()),
            scopes: vec!["organization:manage".to_owned()],
            expires_at: None,
        };

        assert!(validate_service_account_request(&request).is_err());
    }

    #[test]
    fn workspace_role_does_not_grant_organization_permission() {
        let organization_id = Uuid::now_v7();
        let workspace_id = Uuid::now_v7();
        let context = user_context(
            organization_id,
            workspace_id,
            OrganizationRole::Member,
            WorkspaceRole::Owner,
        );

        assert!(
            context
                .require_organization(organization_id, Permission::ManageWorkspace)
                .is_err()
        );
        assert!(
            context
                .require_workspace(workspace_id, Permission::ManageWorkspace)
                .is_ok()
        );
    }

    #[test]
    fn organization_role_grants_organization_permission() {
        let organization_id = Uuid::now_v7();
        let workspace_id = Uuid::now_v7();
        let context = user_context(
            organization_id,
            workspace_id,
            OrganizationRole::Owner,
            WorkspaceRole::Viewer,
        );

        assert!(
            context
                .require_organization(organization_id, Permission::ManageOrganization)
                .is_ok()
        );
    }

    #[test]
    fn organization_owner_does_not_inherit_workspace_permissions() {
        let organization_id = Uuid::now_v7();
        let workspace_id = Uuid::now_v7();
        let context = user_context(
            organization_id,
            workspace_id,
            OrganizationRole::Owner,
            WorkspaceRole::Viewer,
        );

        assert!(
            context
                .require_organization(organization_id, Permission::ManageOrganization)
                .is_ok()
        );
        assert!(
            context
                .require_workspace(workspace_id, Permission::ManageWorkspace)
                .is_err()
        );
    }

    #[test]
    fn platform_support_grant_uses_the_selected_workspace_without_membership() {
        let organization_id = Uuid::now_v7();
        let workspace_id = Uuid::now_v7();
        let mut context = user_context(
            organization_id,
            workspace_id,
            OrganizationRole::Member,
            WorkspaceRole::Viewer,
        );
        context.organization_role = None;
        context.workspace_role = None;
        context.tenant_access_grant_id = Some(Uuid::now_v7());

        assert!(
            context
                .require_organization(organization_id, Permission::ManageOrganization)
                .is_ok()
        );
        assert!(
            context
                .require_workspace(workspace_id, Permission::ManageWorkspace)
                .is_ok()
        );
        assert!(
            context
                .require_workspace(Uuid::now_v7(), Permission::ReadWorkspace)
                .is_err()
        );
    }

    #[test]
    fn workspace_service_account_cannot_cross_into_organization_routes() {
        let organization_id = Uuid::now_v7();
        let workspace_id = Uuid::now_v7();
        let context = service_account_context(
            organization_id,
            Some(workspace_id),
            ["organization:manage", "workspace:manage"],
        );

        assert!(
            context
                .require_organization(organization_id, Permission::ManageOrganization)
                .is_err()
        );
        assert!(
            context
                .require_workspace(workspace_id, Permission::ManageWorkspace)
                .is_ok()
        );
        assert!(
            context
                .require_workspace(Uuid::now_v7(), Permission::ManageWorkspace)
                .is_err()
        );
    }

    #[test]
    fn organization_service_account_can_use_organization_scope() {
        let organization_id = Uuid::now_v7();
        let context = service_account_context(organization_id, None, ["organization:manage"]);

        assert!(
            context
                .require_organization(organization_id, Permission::ManageOrganization)
                .is_ok()
        );
    }

    #[test]
    fn recent_authentication_requires_a_fresh_user_session() {
        let organization_id = Uuid::now_v7();
        let workspace_id = Uuid::now_v7();
        let mut user = user_context(
            organization_id,
            workspace_id,
            OrganizationRole::Owner,
            WorkspaceRole::Owner,
        );
        assert!(user.require_recent_authentication().is_ok());

        user.authenticated_at = Some(OffsetDateTime::now_utc() - time::Duration::minutes(11));
        assert!(matches!(
            user.require_recent_authentication(),
            Err(ApiError::ReauthenticationRequired)
        ));

        let service_account =
            service_account_context(organization_id, None, ["organization:manage"]);
        assert!(matches!(
            service_account.require_recent_authentication(),
            Err(ApiError::Forbidden)
        ));
    }

    #[test]
    fn oauth_credential_endpoints_do_not_depend_on_an_incidental_web_session_cookie() {
        assert!(browser_write_security_exempt("/oauth2/token"));
        assert!(browser_write_security_exempt("/oauth2/userinfo"));
        assert!(browser_write_security_exempt("/oauth2/revoke"));
        assert!(!browser_write_security_exempt("/oauth2/logout"));
        assert!(!browser_write_security_exempt(
            "/api/v1/users/me/oidc-authorization-requests/request-id"
        ));
    }

    #[test]
    fn current_user_times_are_rfc3339_strings() {
        let response = CurrentUserResponse {
            principal_kind: "user".to_owned(),
            principal_id: Uuid::now_v7(),
            user_id: None,
            tenant_access_grant_id: None,
            tenant_access_expires_at: None,
            organization_id: None,
            workspace_id: None,
            organization_role: None,
            workspace_role: None,
            scopes: Vec::new(),
            email: None,
            display_name: "User".to_owned(),
            email_verified_at: None,
            platform_roles: Vec::new(),
            auth_methods: vec!["password".to_owned()],
            has_native_password: true,
            totp_enabled: false,
            mfa_required: false,
            authenticated_at: Some(OffsetDateTime::UNIX_EPOCH),
            mfa_satisfied_at: None,
            idle_expires_at: Some(OffsetDateTime::UNIX_EPOCH),
            absolute_expires_at: Some(OffsetDateTime::UNIX_EPOCH),
        };

        let value = serde_json::to_value(response).expect("serialize current user");
        assert_eq!(value["authenticated_at"], "1970-01-01T00:00:00Z");
        assert_eq!(value["idle_expires_at"], "1970-01-01T00:00:00Z");
        assert_eq!(value["absolute_expires_at"], "1970-01-01T00:00:00Z");
    }

    fn user_context(
        organization_id: Uuid,
        workspace_id: Uuid,
        organization_role: OrganizationRole,
        workspace_role: WorkspaceRole,
    ) -> AuthContext {
        AuthContext {
            principal_kind: PrincipalKind::User,
            principal_id: Uuid::now_v7(),
            user_id: Some(Uuid::now_v7()),
            session_id: Some(Uuid::now_v7()),
            tenant_access_grant_id: None,
            tenant_access_reason: None,
            tenant_access_expires_at: None,
            organization_id,
            workspace_id: Some(workspace_id),
            organization_role: Some(organization_role),
            workspace_role: Some(workspace_role),
            scopes: BTreeSet::new(),
            email: Some("user@example.com".to_owned()),
            display_name: "User".to_owned(),
            authenticated_at: Some(OffsetDateTime::now_utc()),
            mfa_satisfied_at: None,
            platform_roles: BTreeSet::new(),
        }
    }

    fn service_account_context<const N: usize>(
        organization_id: Uuid,
        workspace_id: Option<Uuid>,
        scopes: [&str; N],
    ) -> AuthContext {
        AuthContext {
            principal_kind: PrincipalKind::ServiceAccount,
            principal_id: Uuid::now_v7(),
            user_id: None,
            session_id: None,
            tenant_access_grant_id: None,
            tenant_access_reason: None,
            tenant_access_expires_at: None,
            organization_id,
            workspace_id,
            organization_role: None,
            workspace_role: None,
            scopes: scopes.into_iter().map(ToOwned::to_owned).collect(),
            email: None,
            display_name: "Service Account".to_owned(),
            authenticated_at: None,
            mfa_satisfied_at: None,
            platform_roles: BTreeSet::new(),
        }
    }
}
