use axum::Router;

pub mod agents;
pub mod integrations;
pub mod organization;
pub mod platform_tenants;

use crate::AppState;

/// Registers tenant administration and versioned Agent configuration routes.
pub fn routes() -> Router<AppState> {
    Router::new()
        .merge(organization::routes())
        .merge(platform_tenants::routes())
        .merge(agents::routes())
        .merge(integrations::routes())
}
