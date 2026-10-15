use axum::Router;

pub mod code_workspace;
pub mod model;
pub mod runtime;
pub mod sandbox;
pub mod supervisor;

use crate::{AppState, execution_api};

/// Registers Session, Run, Approval, Trace, and Child Run routes.
pub fn routes() -> Router<AppState> {
    execution_api::routes()
}
