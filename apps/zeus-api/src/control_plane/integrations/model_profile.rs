use axum::{
    Json,
    extract::{OriginalUri, Path, Query, State},
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
    empty_object, ensure_active_model_connection, etag_headers, normalize_model_base_url,
    require_object, validate_model_profile_request, validate_model_provider_kind, validate_name,
};

#[derive(Debug, Serialize, ToSchema, FromRow)]
pub struct ModelProfileResponse {
    pub id: Uuid,
    pub organization_id: Uuid,
    pub workspace_id: Option<Uuid>,
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
    OriginalUri(uri): OriginalUri,
    Path(workspace_id): Path<Uuid>,
    Query(page): Query<PageQuery>,
) -> Result<Json<ModelProfilePageResponse>, ApiError> {
    let workspace_id = super::integration_scope(&auth, &uri, workspace_id, false, true)?;
    let limit = page.limit()?;
    let cursor = page.decoded_cursor()?;
    let mut transaction =
        begin_tenant(&state.platform.database, auth.tenant_scope(workspace_id)).await?;
    let mut items = sqlx::query_as::<_, ModelProfileResponse>(
        "select id, organization_id, workspace_id, connection_id, name,
                provider_kind, base_url, model, configuration, revision,
                created_at, updated_at, archived_at
         from model_profiles
         where organization_id = $1 and workspace_id is not distinct from $2
           and ($6::bool or (archived_at is null and exists (
             select 1 from connections c where c.id = model_profiles.connection_id and c.organization_id = model_profiles.organization_id and c.archived_at is null
           )))
           and ($3::timestamptz is null or (created_at, id) < ($3, $4))
         order by created_at desc, id desc
         limit $5",
    )
    .bind(auth.organization_id)
    .bind(workspace_id)
    .bind(cursor.map(ListCursor::created_at))
    .bind(cursor.map(ListCursor::id))
    .bind(limit + 1)
    .bind(uri.path().starts_with("/api/v1/organizations/"))
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
    OriginalUri(uri): OriginalUri,
    Path(workspace_id): Path<Uuid>,
    Json(request): Json<CreateModelProfileRequest>,
) -> Result<(StatusCode, HeaderMap, Json<ModelProfileResponse>), ApiError> {
    let workspace_id = super::integration_scope(&auth, &uri, workspace_id, true, true)?;
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
    let mut transaction =
        begin_tenant(&state.platform.database, auth.tenant_scope(workspace_id)).await?;
    ensure_active_model_connection(
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
        workspace_id,
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
    OriginalUri(uri): OriginalUri,
    Path((workspace_id, model_profile_id)): Path<(Uuid, Uuid)>,
) -> Result<(HeaderMap, Json<ModelProfileResponse>), ApiError> {
    let workspace_id = super::integration_scope(&auth, &uri, workspace_id, false, true)?;
    let mut transaction =
        begin_tenant(&state.platform.database, auth.tenant_scope(workspace_id)).await?;
    let profile = sqlx::query_as::<_, ModelProfileResponse>(
        "select id, organization_id, workspace_id, connection_id, name,
                provider_kind, base_url, model, configuration, revision,
                created_at, updated_at, archived_at
         from model_profiles
         where id = $1 and organization_id = $2 and workspace_id is not distinct from $3",
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
    OriginalUri(uri): OriginalUri,
    Path((workspace_id, model_profile_id)): Path<(Uuid, Uuid)>,
    headers: HeaderMap,
    Json(request): Json<UpdateModelProfileRequest>,
) -> Result<(HeaderMap, Json<ModelProfileResponse>), ApiError> {
    let workspace_id = super::integration_scope(&auth, &uri, workspace_id, true, true)?;
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

    let mut transaction =
        begin_tenant(&state.platform.database, auth.tenant_scope(workspace_id)).await?;
    if let Some(connection_id) = request.connection_id {
        ensure_active_model_connection(
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
         where id = $8 and organization_id = $9 and workspace_id is not distinct from $10 and revision = $11
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
        workspace_id,
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
    OriginalUri(uri): OriginalUri,
    Path((workspace_id, model_profile_id)): Path<(Uuid, Uuid)>,
    headers: HeaderMap,
) -> Result<(HeaderMap, Json<ModelProfileResponse>), ApiError> {
    let workspace_id = super::integration_scope(&auth, &uri, workspace_id, true, true)?;
    let revision = required_revision(&headers)?;
    let mut transaction =
        begin_tenant(&state.platform.database, auth.tenant_scope(workspace_id)).await?;
    let profile = sqlx::query_as::<_, ModelProfileResponse>(
        "update model_profiles
         set archived_at = coalesce(archived_at, now()),
             revision = revision + 1,
             updated_at = now()
         where id = $1 and organization_id = $2 and workspace_id is not distinct from $3 and revision = $4
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
        workspace_id,
        "model_profile.archived",
        "model_profile",
        model_profile_id,
    )
    .await?;
    transaction.commit().await?;
    Ok((etag_headers(profile.revision)?, Json(profile)))
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ModelConnectionTestResponse {
    pub success: bool,
    pub code: String,
    #[serde(with = "time::serde::rfc3339")]
    pub checked_at: OffsetDateTime,
    pub model_revision: i64,
}

// One bounded, explicit diagnostic request. No business input or provider body is returned.
pub async fn test_model_connection(
    State(state): State<AppState>,
    auth: AuthContext,
    OriginalUri(uri): OriginalUri,
    Path((organization_id, model_profile_id)): Path<(Uuid, Uuid)>,
    headers: HeaderMap,
) -> Result<Json<ModelConnectionTestResponse>, ApiError> {
    use crate::{crypto::SealedSecret, execution::model::OpenAiCompatibleAdapter};
    use secrecy::SecretString;
    let scope = super::integration_scope(&auth, &uri, organization_id, true, true)?;
    let revision = required_revision(&headers)?;
    let mut transaction = begin_tenant(&state.platform.database, auth.tenant_scope(scope)).await?;
    let profile = sqlx::query_as::<_, ModelProfileResponse>(
        "select id, organization_id, workspace_id, connection_id, name, provider_kind, base_url, model, configuration, revision, created_at, updated_at, archived_at
         from model_profiles where id=$1 and organization_id=$2 and workspace_id is null and archived_at is null",
    ).bind(model_profile_id).bind(auth.organization_id).fetch_one(&mut *transaction).await?;
    if profile.revision != revision {
        return Err(ApiError::PreconditionFailed);
    }
    let credential = sqlx::query_as::<_, (String, Vec<u8>, Vec<u8>, String)>(
        "select s.secret_name, s.ciphertext, s.nonce, s.key_id from connections c
         join connection_secrets s on s.connection_id=c.id and s.organization_id=c.organization_id and s.workspace_id is null
         where c.id=$1 and c.organization_id=$2 and c.workspace_id is null and c.archived_at is null
           and s.secret_name=coalesce(c.configuration->>'api_key_secret_name','api_key')",
    ).bind(profile.connection_id).bind(auth.organization_id).fetch_optional(&mut *transaction).await?;
    insert_audit(
        &mut transaction,
        &auth,
        None,
        "model_profile.connection_test_requested",
        "model_profile",
        model_profile_id,
    )
    .await?;
    transaction.commit().await?;
    let result = if let Some((name, ciphertext, nonce, key_id)) = credential {
        let plaintext = state
            .platform
            .envelope
            .open(
                &SealedSecret {
                    ciphertext,
                    nonce,
                    key_id,
                },
                format!("connection/{}/{name}", profile.connection_id).as_bytes(),
            )
            .map_err(|_| ApiError::Internal)?;
        let secret =
            SecretString::from(String::from_utf8(plaintext).map_err(|_| ApiError::Internal)?);
        let mut configuration = profile
            .configuration
            .as_object()
            .cloned()
            .unwrap_or_default();
        configuration.remove("timeout_ms");
        configuration.remove("request_timeout_ms");
        configuration.insert("timeout_seconds".to_owned(), serde_json::json!(20));
        match OpenAiCompatibleAdapter::new(
            &profile.base_url,
            &profile.model,
            secret,
            Value::Object(configuration),
        ) {
            Ok(adapter) => adapter.check_connection().await,
            Err(error) => Err(error),
        }
    } else {
        return Ok(Json(ModelConnectionTestResponse {
            success: false,
            code: "credential_missing".to_owned(),
            checked_at: OffsetDateTime::now_utc(),
            model_revision: revision,
        }));
    };
    Ok(Json(ModelConnectionTestResponse {
        success: matches!(result, Ok(true)),
        code: if matches!(result, Ok(false)) {
            "model_not_listed"
        } else {
            connection_test_code(result.as_ref().err())
        }
        .to_owned(),
        checked_at: OffsetDateTime::now_utc(),
        model_revision: revision,
    }))
}

fn connection_test_code(error: Option<&crate::execution::model::ModelError>) -> &'static str {
    use crate::execution::model::ModelError;
    match error {
        None => "ok",
        Some(ModelError::HttpStatus { status: 401 | 403 }) => "authentication_failed",
        Some(&ModelError::HttpStatus { status: 404 }) => "endpoint_or_model_not_found",
        Some(ModelError::Timeout) => "timeout",
        Some(ModelError::RateLimited { .. } | ModelError::HttpStatus { status: 429 }) => {
            "rate_limited"
        }
        Some(ModelError::Transport) => "connection_failed",
        Some(ModelError::InvalidConfiguration) => "invalid_configuration",
        Some(ModelError::InvalidResponse | ModelError::StreamInterrupted) => "invalid_response",
        Some(_) => "provider_rejected",
    }
}

#[cfg(test)]
mod connection_test_tests {
    use super::connection_test_code;
    use crate::execution::model::ModelError;
    #[test]
    fn diagnostic_time_is_an_rfc3339_string() {
        let response = super::ModelConnectionTestResponse {
            success: true,
            code: "ok".to_owned(),
            checked_at: time::OffsetDateTime::UNIX_EPOCH,
            model_revision: 1,
        };
        let value = serde_json::to_value(response).expect("diagnostic response");
        assert_eq!(value["checked_at"], "1970-01-01T00:00:00Z");
    }

    #[test]
    fn exposes_stable_diagnostic_codes_only() {
        assert_eq!(connection_test_code(None), "ok");
        assert_eq!(
            connection_test_code(Some(&ModelError::HttpStatus { status: 401 })),
            "authentication_failed"
        );
        assert_eq!(connection_test_code(Some(&ModelError::Timeout)), "timeout");
        assert_eq!(
            connection_test_code(Some(&ModelError::HttpStatus { status: 404 })),
            "endpoint_or_model_not_found"
        );
    }
}
