use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sqlx::FromRow;
use time::OffsetDateTime;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::api_support::PageQuery;

fn empty_object() -> Value {
    json!({})
}

fn user_message_kind() -> String {
    "user_message".to_owned()
}

#[derive(Debug, Serialize, ToSchema, FromRow)]
pub struct SessionResponse {
    pub id: Uuid,
    pub organization_id: Uuid,
    pub workspace_id: Uuid,
    pub work_item_id: Option<Uuid>,
    pub title: String,
    pub status: String,
    pub created_by: Option<Uuid>,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
    pub closed_at: Option<OffsetDateTime>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct SessionPageResponse {
    pub items: Vec<SessionResponse>,
    pub next_cursor: Option<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateSessionRequest {
    pub work_item_id: Option<Uuid>,
    #[serde(default)]
    pub title: String,
}

#[derive(Debug, Deserialize, Serialize, ToSchema)]
pub struct SubmitMessageRequest {
    #[serde(default = "user_message_kind")]
    pub kind: String,
    pub content: String,
}

#[derive(Debug, Serialize, ToSchema, FromRow)]
pub struct AppendedEventResponse {
    pub event_id: Uuid,
    pub event_sequence: i64,
}

#[derive(Debug, Serialize, ToSchema, FromRow)]
pub struct SessionEventResponse {
    pub id: Uuid,
    pub session_id: Uuid,
    pub run_id: Option<Uuid>,
    pub sequence: i64,
    pub schema_version: i16,
    pub event_type: String,
    pub actor_kind: String,
    pub actor_id: Option<Uuid>,
    pub payload: Value,
    pub occurred_at: OffsetDateTime,
}

#[derive(Debug, Default, Deserialize)]
pub struct EventQuery {
    #[serde(default)]
    pub after: i64,
    pub limit: Option<u16>,
}

#[derive(Debug, Deserialize, Serialize, ToSchema)]
pub struct CreateRunRequest {
    pub workflow_version_id: Uuid,
    pub session_id: Uuid,
    pub work_item_id: Option<Uuid>,
    #[serde(default = "empty_object")]
    pub input: Value,
    pub message: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, ToSchema)]
pub struct StartWorkItemRunRequest {
    pub workflow_id: Uuid,
    #[serde(default = "empty_object")]
    pub input: Value,
    pub message: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, ToSchema, FromRow)]
pub struct RunResponse {
    pub id: Uuid,
    pub organization_id: Uuid,
    pub workspace_id: Uuid,
    pub workflow_version_id: Uuid,
    pub work_item_id: Option<Uuid>,
    pub session_id: Uuid,
    pub parent_run_id: Option<Uuid>,
    pub retry_of_run_id: Option<Uuid>,
    pub status: String,
    pub input: Value,
    pub output: Option<Value>,
    pub error_code: Option<String>,
    pub error_detail: Option<String>,
    pub attempt_count: i32,
    pub cancel_requested_at: Option<OffsetDateTime>,
    pub started_at: Option<OffsetDateTime>,
    pub finished_at: Option<OffsetDateTime>,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct RunPageResponse {
    pub items: Vec<RunResponse>,
    pub next_cursor: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct WorkItemRunStartResponse {
    pub session: SessionResponse,
    pub run: RunResponse,
}

#[derive(Debug, Default, Deserialize)]
pub struct RunQuery {
    #[serde(flatten)]
    pub page: PageQuery,
    pub work_item_id: Option<Uuid>,
    pub status: Option<String>,
}

#[derive(Debug, Serialize, ToSchema, FromRow)]
pub struct RunEventResponse {
    pub id: Uuid,
    pub run_id: Uuid,
    pub session_event_id: Option<Uuid>,
    pub sequence: i64,
    pub schema_version: i16,
    pub event_type: String,
    pub payload: Value,
    pub occurred_at: OffsetDateTime,
}

#[derive(Debug, Serialize, ToSchema, FromRow)]
pub struct RunUsageResponse {
    pub id: Uuid,
    pub run_id: Uuid,
    pub provider_request_id: String,
    pub prompt_tokens: i64,
    pub completion_tokens: i64,
    pub cache_tokens: i64,
    pub occurred_at: OffsetDateTime,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct RunUsageSummaryResponse {
    pub prompt_tokens: i64,
    pub completion_tokens: i64,
    pub cache_tokens: i64,
    pub entries: Vec<RunUsageResponse>,
}

#[derive(Debug, Serialize, ToSchema, FromRow)]
pub struct ApprovalResponse {
    pub id: Uuid,
    pub run_id: Uuid,
    pub tool_call_id: Uuid,
    pub status: String,
    pub requested_at: OffsetDateTime,
    pub expires_at: Option<OffsetDateTime>,
    pub decided_at: Option<OffsetDateTime>,
    pub decided_by: Option<Uuid>,
    pub reason: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
pub struct ApprovalQuery {
    pub status: Option<String>,
    pub work_item_id: Option<Uuid>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct DecideApprovalRequest {
    pub reason: Option<String>,
}

#[derive(Debug, Default, Deserialize, ToSchema)]
pub struct CancelRunRequest {
    pub reason: Option<String>,
}

#[derive(Debug, Default, Deserialize, Serialize, ToSchema)]
pub struct RetryRunRequest {}

#[derive(Debug, Serialize, ToSchema, FromRow)]
pub struct TraceToolCallResponse {
    pub id: Uuid,
    pub capability_id: Uuid,
    pub call_key: String,
    pub status: String,
    pub input: Value,
    pub result: Option<Value>,
    pub error_code: Option<String>,
    pub child_run_id: Option<Uuid>,
    pub started_at: Option<OffsetDateTime>,
    pub finished_at: Option<OffsetDateTime>,
    pub created_at: OffsetDateTime,
}

#[derive(Debug, Serialize, ToSchema, FromRow)]
pub struct TraceRunLinkResponse {
    pub relation: String,
    pub run_id: Uuid,
    pub status: String,
    pub output: Option<Value>,
    pub error_code: Option<String>,
    pub created_at: OffsetDateTime,
}

#[derive(Debug, Serialize, ToSchema, FromRow)]
pub struct ChildRunResponse {
    pub id: Uuid,
    pub workflow_version_id: Uuid,
    pub session_id: Uuid,
    pub status: String,
    pub depth: i16,
    pub token_budget: i64,
    pub max_runtime_seconds: i32,
    pub output: Option<Value>,
    pub error_code: Option<String>,
    pub error_detail: Option<String>,
    pub created_at: OffsetDateTime,
    pub finished_at: Option<OffsetDateTime>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct TraceExperienceInjectionResponse {
    pub id: Uuid,
    pub experience_entry_id: Uuid,
    pub experience_version: i32,
    pub rank: f32,
    pub query_sha256: String,
    pub injected_at: OffsetDateTime,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct RunTraceResponse {
    pub run: RunResponse,
    pub run_events: Vec<RunEventResponse>,
    pub session_events: Vec<SessionEventResponse>,
    pub tool_calls: Vec<TraceToolCallResponse>,
    pub approvals: Vec<ApprovalResponse>,
    pub usage: RunUsageSummaryResponse,
    pub linked_runs: Vec<TraceRunLinkResponse>,
    pub experience_injections: Vec<TraceExperienceInjectionResponse>,
}
