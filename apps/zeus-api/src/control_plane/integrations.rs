#![allow(clippy::missing_errors_doc)] // HTTP failures use the shared Problem Details contract.

mod capability;
mod connection;
mod model_profile;
mod schedule;
mod webhook;

pub use capability::{
    CapabilityDefinitionPageResponse, CapabilityDefinitionResponse,
    CreateCapabilityDefinitionRequest, CreateWorkspaceCapabilityRequest,
    UpdateCapabilityDefinitionRequest, UpdateWorkspaceCapabilityRequest,
    WorkspaceCapabilityPageResponse, WorkspaceCapabilityResponse, archive_capability_definition,
    create_capability_definition, create_workspace_capability, disable_workspace_capability,
    enable_workspace_capability, get_capability_definition, get_workspace_capability,
    list_capabilities, list_capability_definitions, update_capability_definition,
    update_workspace_capability,
};
pub use connection::{
    ConnectionPageResponse, ConnectionResponse, ConnectionSecretPageResponse,
    ConnectionSecretResponse, ConnectionSecretValueRequest, CreateConnectionRequest,
    CreateConnectionSecretRequest, UpdateConnectionRequest, archive_connection, create_connection,
    create_connection_secret, create_named_connection_secret, get_connection,
    list_connection_secrets, list_connections, rotate_connection_secret, update_connection,
};
pub use model_profile::{
    CreateModelProfileRequest, ModelProfilePageResponse, ModelProfileResponse,
    UpdateModelProfileRequest, archive_model_profile, create_model_profile, get_model_profile,
    list_model_profiles, update_model_profile,
};
pub use schedule::{
    CreateScheduleRequest, SchedulePageResponse, ScheduleResponse, UpdateScheduleRequest,
    create_schedule, disable_schedule, enable_schedule, get_schedule, list_schedules,
    update_schedule,
};
pub use webhook::{
    CreateWebhookEndpointRequest, CreatedWebhookEndpointResponse, UpdateWebhookEndpointRequest,
    WebhookEndpointPageResponse, WebhookEndpointResponse, create_webhook_endpoint,
    disable_webhook_endpoint, enable_webhook_endpoint, get_webhook_endpoint,
    list_webhook_endpoints, update_webhook_endpoint,
};

use std::collections::BTreeMap;

use axum::{
    Json, Router,
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde_json::{Value, json};
use sqlx::{Postgres, Transaction};
use url::Url;
use uuid::Uuid;

use crate::{AppState, api_support::revision_etag, error::ApiError, oidc::validate_remote_url};

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
        .platform
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

fn default_enabled() -> bool {
    true
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
