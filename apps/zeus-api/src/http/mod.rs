mod openapi;
mod operations;
mod router;

pub use openapi::ApiDoc;
pub use router::router;

#[cfg(test)]
use openapi::{
    PUBLIC_ROUTES, has_oauth_error_response, has_problem_response, uses_oauth_error_contract,
};
#[cfg(test)]
use router::{request_id_from_headers, should_track_http_path};

include!("tests.rs");
