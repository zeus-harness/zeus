use axum::Router;

pub mod experiences;
pub mod im;
pub mod im_agents;
pub mod work_item_archive;
pub mod work_items;

use crate::AppState;

/// Registers `WorkItem` and reviewed team experience routes.
pub fn routes() -> Router<AppState> {
    Router::new()
        .merge(work_items::routes())
        .merge(work_item_archive::routes())
        .merge(im::routes())
        .merge(im_agents::routes())
        .merge(experiences::routes())
}
