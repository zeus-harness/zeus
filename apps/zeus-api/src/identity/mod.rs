use axum::Router;

pub mod auth;
pub mod federated_identity;
pub mod maintenance;
pub mod native_auth;
pub mod native_identity;
pub mod oidc;
pub mod oidc_provider;
pub mod organization_identity;

use crate::AppState;

/// Registers native identity, federation, invitations, and the Zeus OIDC Provider routes.
pub fn routes() -> Router<AppState> {
    Router::new()
        .merge(auth::routes())
        .merge(native_auth::routes())
        .merge(native_identity::routes())
        .merge(organization_identity::routes())
        .merge(federated_identity::routes())
        .merge(oidc_provider::routes())
}
