use axum::Router;

pub mod experiences;
pub mod work_items;

use crate::AppState;

/// Registers `WorkItem` and reviewed team experience routes.
pub fn routes() -> Router<AppState> {
    Router::new()
        .merge(work_items::routes())
        .merge(experiences::routes())
}
