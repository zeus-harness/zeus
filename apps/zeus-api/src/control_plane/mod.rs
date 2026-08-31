use axum::Router;

pub mod agents;
pub mod integrations;
pub mod organization;

use crate::AppState;

/// Registers tenant administration and versioned Agent configuration routes.
pub fn routes() -> Router<AppState> {
    Router::new()
        .merge(organization::routes())
        .merge(agents::routes())
        .merge(integrations::routes())
}
