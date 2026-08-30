#![allow(clippy::missing_errors_doc)] // Protocol and API failures use their transport contracts.

mod authorization;
mod client;
mod keys;
mod token;

use std::sync::Arc;

use axum::Router;
use axum::http::{Method, header};
use sqlx::{FromRow, PgPool};
use tower_http::cors::{Any, CorsLayer};
use uuid::Uuid;

use crate::{AppState, crypto::EnvelopeCipher, error::ApiError};

pub use authorization::{
    AuthorizationDecisionRequest, AuthorizationDecisionResponse, AuthorizationRequestResponse,
};
pub use client::{
    CreateOidcClientRequest, CreatedOidcClientResponse, OidcClientResponse, OidcGrantResponse,
    UpdateOidcClientRequest,
};

#[derive(Clone, Debug, FromRow)]
pub(crate) struct ProtocolClient {
    pub id: Uuid,
    pub organization_id: Uuid,
    pub client_id: String,
    pub client_type: String,
    pub client_secret_hash: Option<String>,
    pub allowed_scopes: Vec<String>,
    pub redirect_uris: Vec<String>,
    pub post_logout_redirect_uris: Vec<String>,
}

pub(crate) async fn load_protocol_client(
    state: &AppState,
    client_id: &str,
) -> Result<ProtocolClient, ApiError> {
    sqlx::query_as::<_, ProtocolClient>("select * from zeus_private.load_oidc_client($1)")
        .bind(client_id)
        .fetch_optional(&state.database)
        .await?
        .ok_or(ApiError::Unauthorized)
}

pub fn routes() -> Router<AppState> {
    let browser_protocol = Router::new()
        .merge(token::protocol_routes())
        .merge(keys::routes())
        .layer(
            CorsLayer::new()
                .allow_origin(Any)
                .allow_methods([Method::GET, Method::POST])
                .allow_headers([header::AUTHORIZATION, header::CONTENT_TYPE])
                .max_age(std::time::Duration::from_mins(10)),
        );
    Router::new()
        .merge(client::routes())
        .merge(authorization::routes())
        .merge(token::logout_routes())
        .merge(browser_protocol)
}

pub(crate) async fn maintain_signing_key(
    database: &PgPool,
    envelope: &Arc<dyn EnvelopeCipher>,
) -> Result<(), ApiError> {
    keys::maintain_signing_key(database, envelope.as_ref()).await
}
