#![allow(clippy::missing_errors_doc)] // HTTP failures use the shared Problem Details contract.

mod approval;
mod event_trace;
mod run;
mod session;
mod shared;

#[cfg(test)]
use event_trace::{event_limit, last_event_sequence};
#[cfg(test)]
use run::{validate_run_input, validate_run_status_filter};

pub use approval::{__path_list_approvals, approve, list_approvals, reject};
pub use event_trace::{
    get_run_trace, get_run_usage, list_child_runs, list_run_events, list_session_events,
    stream_run_events,
};
pub use run::{
    __path_create_run, __path_list_runs, __path_start_work_item_run, cancel_run, create_run,
    get_run, list_runs, retry_run, start_work_item_run,
};
pub use session::{create_session, get_session, list_sessions, submit_message};
pub use shared::types::{
    AppendedEventResponse, ApprovalQuery, ApprovalResponse, CancelRunRequest, ChildRunResponse,
    CreateRunRequest, CreateSessionRequest, DecideApprovalRequest, EventQuery, RetryRunRequest,
    RunEventResponse, RunPageResponse, RunQuery, RunResponse, RunTraceResponse, RunUsageResponse,
    RunUsageSummaryResponse, SessionEventResponse, SessionPageResponse, SessionResponse,
    StartWorkItemRunRequest, SubmitMessageRequest, TraceExperienceInjectionResponse,
    TraceRunLinkResponse, TraceToolCallResponse, WorkItemRunStartResponse,
};

use axum::Router;

use crate::AppState;

/// Registers Session, Run, Approval, Trace, and Child Run routes.
pub fn routes() -> Router<AppState> {
    Router::new()
        .merge(session::routes())
        .merge(run::routes())
        .merge(event_trace::routes())
        .merge(approval::routes())
}

#[cfg(test)]
mod tests {
    use axum::http::{HeaderMap, HeaderValue};
    use serde_json::json;

    use super::{event_limit, last_event_sequence, validate_run_input, validate_run_status_filter};

    #[test]
    fn event_limits_are_bounded() {
        assert_eq!(event_limit(None).unwrap(), 100);
        assert!(event_limit(Some(0)).is_err());
        assert!(event_limit(Some(501)).is_err());
    }

    #[test]
    fn last_event_id_uses_the_event_sequence() {
        let mut headers = HeaderMap::new();
        headers.insert("last-event-id", HeaderValue::from_static("42"));
        assert_eq!(last_event_sequence(&headers).unwrap(), 42);
    }

    #[test]
    fn run_creation_and_filters_reject_invalid_shapes() {
        assert!(validate_run_input(&json!({}), Some("run this task")).is_ok());
        assert!(validate_run_input(&json!([]), None).is_err());
        assert!(validate_run_input(&json!({}), Some(" ")).is_err());
        assert!(validate_run_status_filter(Some("waiting_child")).is_ok());
        assert!(validate_run_status_filter(Some("unknown")).is_err());
    }
}
