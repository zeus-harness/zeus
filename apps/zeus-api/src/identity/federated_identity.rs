#![allow(clippy::missing_errors_doc)] // HTTP failures use the shared Problem Details contract.

use axum::{
    Json, Router,
    extract::{Path, State},
    http::{HeaderMap, StatusCode, header},
    routing::{delete, get, post},
};
use hickory_resolver::{Resolver, proto::rr::RData};
use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use time::OffsetDateTime;
use utoipa::ToSchema;
use uuid::Uuid;
use zeus_core::Permission;

use crate::{
    AppState,
    api_support::{required_revision, revision_etag},
    auth::{AuthContext, insert_audit},
    crypto::{random_token, sha256},
    database::{TenantScope, begin_tenant},
    error::ApiError,
};

const VERIFICATION_PREFIX: &str = "zeus-domain-verification=";

#[derive(Debug, Serialize, ToSchema, FromRow)]
pub struct OrganizationDomainResponse {
    pub id: Uuid,
    pub organization_id: Uuid,
    pub domain: String,
    pub status: String,
    #[serde(with = "time::serde::rfc3339::option")]
    pub verified_at: Option<OffsetDateTime>,
    pub created_by: Uuid,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateOrganizationDomainRequest {
    pub domain: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct CreatedOrganizationDomainResponse {
    #[serde(flatten)]
    pub domain: OrganizationDomainResponse,
    pub txt_record_name: String,
    #[schema(write_only)]
    pub txt_record_value: String,
}

#[derive(Debug, FromRow)]
struct DomainVerificationRow {
    domain: String,
    verification_token_hash: Vec<u8>,
}

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{organization_id}/domains",
    tag = "identity",
    params(("organization_id" = Uuid, Path)),
    responses((status = 200, description = "Verified-domain configuration", body = [OrganizationDomainResponse]))
)]
pub async fn list_domains(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(organization_id): Path<Uuid>,
) -> Result<Json<Vec<OrganizationDomainResponse>>, ApiError> {
    auth.require_organization(organization_id, Permission::ManageOrganization)?;
    let mut transaction = begin_tenant(
        &state.platform.database,
        TenantScope::organization(auth.user_id, organization_id),
    )
    .await?;
    let domains = sqlx::query_as::<_, OrganizationDomainResponse>(
        "select id, organization_id, domain, status, verified_at,
                created_by, created_at, updated_at
         from organization_domains
         where organization_id = $1
         order by created_at desc, id desc",
    )
    .bind(organization_id)
    .fetch_all(&mut *transaction)
    .await?;
    transaction.commit().await?;
    Ok(Json(domains))
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{organization_id}/domains",
    tag = "identity",
    params(("organization_id" = Uuid, Path)),
    request_body = CreateOrganizationDomainRequest,
    responses((status = 201, description = "Domain verification challenge created", body = CreatedOrganizationDomainResponse))
)]
pub async fn create_domain(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(organization_id): Path<Uuid>,
    Json(request): Json<CreateOrganizationDomainRequest>,
) -> Result<(StatusCode, Json<CreatedOrganizationDomainResponse>), ApiError> {
    auth.require_organization(organization_id, Permission::ManageOrganization)?;
    let user_id = auth.user_id.ok_or(ApiError::Forbidden)?;
    let domain = normalize_domain(&request.domain)?;
    let token = random_token(32).map_err(|_| ApiError::Internal)?;
    let mut transaction = begin_tenant(
        &state.platform.database,
        TenantScope::organization(auth.user_id, organization_id),
    )
    .await?;
    let created = sqlx::query_as::<_, OrganizationDomainResponse>(
        "insert into organization_domains (
           organization_id, domain, verification_token_hash, created_by
         ) values ($1, $2, $3, $4)
         returning id, organization_id, domain, status, verified_at,
                   created_by, created_at, updated_at",
    )
    .bind(organization_id)
    .bind(&domain)
    .bind(sha256(token.expose_secret().as_bytes()))
    .bind(user_id)
    .fetch_one(&mut *transaction)
    .await?;
    insert_audit(
        &mut transaction,
        &auth,
        None,
        "organization_domain.created",
        "organization_domain",
        created.id,
    )
    .await?;
    transaction.commit().await?;
    Ok((
        StatusCode::CREATED,
        Json(CreatedOrganizationDomainResponse {
            txt_record_name: format!("_zeus-verification.{domain}"),
            txt_record_value: format!("{VERIFICATION_PREFIX}{}", token.expose_secret()),
            domain: created,
        }),
    ))
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{organization_id}/domains/{domain_id}/verify",
    tag = "identity",
    params(("organization_id" = Uuid, Path), ("domain_id" = Uuid, Path)),
    responses((status = 200, description = "Domain verified", body = OrganizationDomainResponse))
)]
pub async fn verify_domain(
    State(state): State<AppState>,
    auth: AuthContext,
    Path((organization_id, domain_id)): Path<(Uuid, Uuid)>,
) -> Result<Json<OrganizationDomainResponse>, ApiError> {
    auth.require_organization(organization_id, Permission::ManageOrganization)?;
    let mut transaction = begin_tenant(
        &state.platform.database,
        TenantScope::organization(auth.user_id, organization_id),
    )
    .await?;
    let challenge = sqlx::query_as::<_, DomainVerificationRow>(
        "select domain, verification_token_hash
         from organization_domains
         where id = $1 and organization_id = $2 and status = 'pending'",
    )
    .bind(domain_id)
    .bind(organization_id)
    .fetch_optional(&mut *transaction)
    .await?
    .ok_or(ApiError::NotFound)?;
    transaction.commit().await?;

    let record_name = format!("_zeus-verification.{}.", challenge.domain);
    let records = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        resolve_txt_records(&record_name),
    )
    .await
    .map_err(|_| ApiError::IdentityProvider)??;
    let verified = records.iter().any(|record| {
        record
            .strip_prefix(VERIFICATION_PREFIX)
            .is_some_and(|token| sha256(token.as_bytes()) == challenge.verification_token_hash)
    });
    if !verified {
        return Err(ApiError::Validation(
            "the expected DNS TXT verification record was not found".to_owned(),
        ));
    }

    let mut transaction = begin_tenant(
        &state.platform.database,
        TenantScope::organization(auth.user_id, organization_id),
    )
    .await?;
    let domain = sqlx::query_as::<_, OrganizationDomainResponse>(
        "update organization_domains
         set status = 'verified', verified_at = now(), updated_at = now()
         where id = $1 and organization_id = $2 and status = 'pending'
         returning id, organization_id, domain, status, verified_at,
                   created_by, created_at, updated_at",
    )
    .bind(domain_id)
    .bind(organization_id)
    .fetch_optional(&mut *transaction)
    .await?
    .ok_or(ApiError::Conflict(
        "domain verification state changed".to_owned(),
    ))?;
    insert_audit(
        &mut transaction,
        &auth,
        None,
        "organization_domain.verified",
        "organization_domain",
        domain_id,
    )
    .await?;
    transaction.commit().await?;
    Ok(Json(domain))
}

#[utoipa::path(
    delete,
    path = "/api/v1/organizations/{organization_id}/domains/{domain_id}",
    tag = "identity",
    params(("organization_id" = Uuid, Path), ("domain_id" = Uuid, Path)),
    responses((status = 204, description = "Domain revoked"))
)]
pub async fn revoke_domain(
    State(state): State<AppState>,
    auth: AuthContext,
    Path((organization_id, domain_id)): Path<(Uuid, Uuid)>,
) -> Result<StatusCode, ApiError> {
    auth.require_organization(organization_id, Permission::ManageOrganization)?;
    let mut transaction = begin_tenant(
        &state.platform.database,
        TenantScope::organization(auth.user_id, organization_id),
    )
    .await?;
    let result = sqlx::query(
        "update organization_domains
         set status = 'revoked', verified_at = null, updated_at = now()
         where id = $1 and organization_id = $2 and status <> 'revoked'",
    )
    .bind(domain_id)
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
        "organization_domain.revoked",
        "organization_domain",
        domain_id,
    )
    .await?;
    transaction.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Debug, Serialize, ToSchema, FromRow)]
pub struct OrganizationIdentityPolicyResponse {
    pub organization_id: Uuid,
    pub mfa_required: bool,
    pub federated_required: bool,
    pub required_federated_provider_id: Option<Uuid>,
    pub revision: i64,
    pub updated_by: Option<Uuid>,
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateOrganizationIdentityPolicyRequest {
    pub mfa_required: bool,
    pub federated_required: bool,
    pub required_federated_provider_id: Option<Uuid>,
}

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{organization_id}/identity-policy",
    tag = "identity",
    params(("organization_id" = Uuid, Path)),
    responses((status = 200, description = "Organization identity policy", body = OrganizationIdentityPolicyResponse))
)]
pub async fn get_identity_policy(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(organization_id): Path<Uuid>,
) -> Result<Json<OrganizationIdentityPolicyResponse>, ApiError> {
    auth.require_organization(organization_id, Permission::ManageOrganization)?;
    let mut transaction = begin_tenant(
        &state.platform.database,
        TenantScope::organization(auth.user_id, organization_id),
    )
    .await?;
    let policy = sqlx::query_as::<_, OrganizationIdentityPolicyResponse>(
        "select organization_id, mfa_required, federated_required,
                required_federated_provider_id, revision, updated_by, updated_at
         from organization_identity_policies where organization_id = $1",
    )
    .bind(organization_id)
    .fetch_one(&mut *transaction)
    .await?;
    transaction.commit().await?;
    Ok(Json(policy))
}

#[utoipa::path(
    put,
    path = "/api/v1/organizations/{organization_id}/identity-policy",
    tag = "identity",
    params(("organization_id" = Uuid, Path)),
    request_body = UpdateOrganizationIdentityPolicyRequest,
    responses((status = 200, description = "Organization identity policy updated", body = OrganizationIdentityPolicyResponse))
)]
pub async fn update_identity_policy(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(organization_id): Path<Uuid>,
    headers: HeaderMap,
    Json(request): Json<UpdateOrganizationIdentityPolicyRequest>,
) -> Result<(HeaderMap, Json<OrganizationIdentityPolicyResponse>), ApiError> {
    auth.require_organization(organization_id, Permission::ManageOrganization)?;
    if request.federated_required != request.required_federated_provider_id.is_some() {
        return Err(ApiError::Validation(
            "federated_required requires exactly one organization provider".to_owned(),
        ));
    }
    let revision = required_revision(&headers)?;
    let user_id = auth.user_id.ok_or(ApiError::Forbidden)?;
    let mut transaction = begin_tenant(
        &state.platform.database,
        TenantScope::organization(auth.user_id, organization_id),
    )
    .await?;
    let policy = sqlx::query_as::<_, OrganizationIdentityPolicyResponse>(
        "update organization_identity_policies
         set mfa_required = $1, federated_required = $2,
             required_federated_provider_id = $3,
             revision = revision + 1, updated_by = $4, updated_at = now()
         where organization_id = $5 and revision = $6
         returning organization_id, mfa_required, federated_required,
                   required_federated_provider_id, revision, updated_by, updated_at",
    )
    .bind(request.mfa_required)
    .bind(request.federated_required)
    .bind(request.required_federated_provider_id)
    .bind(user_id)
    .bind(organization_id)
    .bind(revision)
    .fetch_optional(&mut *transaction)
    .await?
    .ok_or(ApiError::PreconditionFailed)?;
    insert_audit(
        &mut transaction,
        &auth,
        None,
        "organization_identity_policy.updated",
        "organization",
        organization_id,
    )
    .await?;
    transaction.commit().await?;
    let mut response_headers = HeaderMap::new();
    response_headers.insert(header::ETAG, revision_etag(policy.revision)?);
    Ok((response_headers, Json(policy)))
}

pub fn routes() -> Router<AppState> {
    Router::new()
        .route(
            "/api/v1/organizations/{organization_id}/domains",
            get(list_domains).post(create_domain),
        )
        .route(
            "/api/v1/organizations/{organization_id}/domains/{domain_id}/verify",
            post(verify_domain),
        )
        .route(
            "/api/v1/organizations/{organization_id}/domains/{domain_id}",
            delete(revoke_domain),
        )
        .route(
            "/api/v1/organizations/{organization_id}/identity-policy",
            get(get_identity_policy).put(update_identity_policy),
        )
}

async fn resolve_txt_records(name: &str) -> Result<Vec<String>, ApiError> {
    let resolver = Resolver::builder_tokio()
        .map_err(|_| ApiError::Internal)?
        .build()
        .map_err(|_| ApiError::Internal)?;
    let lookup = resolver
        .txt_lookup(name)
        .await
        .map_err(|_| ApiError::IdentityProvider)?;
    let mut values = Vec::new();
    for record in lookup.answers() {
        let RData::TXT(txt) = &record.data else {
            continue;
        };
        let bytes = txt
            .txt_data
            .iter()
            .flat_map(|part| part.iter().copied())
            .collect::<Vec<_>>();
        if let Ok(value) = String::from_utf8(bytes) {
            values.push(value);
        }
    }
    Ok(values)
}

fn normalize_domain(value: &str) -> Result<String, ApiError> {
    let domain = value.trim().trim_end_matches('.').to_ascii_lowercase();
    if !(3..=253).contains(&domain.len())
        || !domain.contains('.')
        || domain.parse::<std::net::IpAddr>().is_ok()
        || domain.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || label.bytes().any(|byte| {
                    !byte.is_ascii_lowercase() && !byte.is_ascii_digit() && byte != b'-'
                })
        })
    {
        return Err(ApiError::Validation("domain is invalid".to_owned()));
    }
    Ok(domain)
}

#[cfg(test)]
mod tests {
    use super::normalize_domain;

    #[test]
    fn organization_domains_are_canonical_and_not_ip_addresses() {
        assert_eq!(normalize_domain(" Example.COM. ").unwrap(), "example.com");
        assert!(normalize_domain("localhost").is_err());
        assert!(normalize_domain("127.0.0.1").is_err());
        assert!(normalize_domain("-bad.example").is_err());
    }
}
