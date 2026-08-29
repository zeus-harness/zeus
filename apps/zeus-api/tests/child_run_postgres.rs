use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use axum::{Json, Router, extract::State, response::Response, routing::post};
use http::{HeaderValue, StatusCode, header};
use secrecy::SecretString;
use serde_json::{Value, json};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;
use zeus_api::{
    RUNTIME_DATABASE_ROLE, connect_pool, connect_pool_as_role,
    crypto::{EnvelopeCipher, LocalEnvelopeCipher},
    migrate,
    runtime::DurableRunExecutor,
    supervisor::{ClaimedRun, RunExecutor, RunOutcome},
};

#[tokio::test]
#[ignore = "requires ZEUS_TEST_DATABASE_URL and ZEUS_TEST_ENVELOPE_KEY"]
#[allow(clippy::too_many_lines)] // One flow proves persistent parent/child hand-off and resume.
async fn child_run_uses_separate_session_budgets_and_durable_parent_resume() {
    let database_url = std::env::var("ZEUS_TEST_DATABASE_URL")
        .expect("ZEUS_TEST_DATABASE_URL is required for this ignored test");
    let envelope_key = SecretString::from(
        std::env::var("ZEUS_TEST_ENVELOPE_KEY")
            .expect("ZEUS_TEST_ENVELOPE_KEY is required for this ignored test"),
    );
    let owner_pool = connect_pool(&database_url, 5)
        .await
        .expect("test database connects");
    migrate(&owner_pool).await.expect("test database migrates");

    let organization_id = Uuid::now_v7();
    let workspace_id = Uuid::now_v7();
    let connection_id = Uuid::now_v7();
    let model_profile_id = Uuid::now_v7();
    let agent_id = Uuid::now_v7();
    let agent_version_id = Uuid::now_v7();
    let workflow_id = Uuid::now_v7();
    let workflow_version_id = Uuid::now_v7();
    let capability_id = Uuid::now_v7();
    let parent_session_id = Uuid::now_v7();
    let parent_run_id = Uuid::now_v7();
    let model_tool_name = format!("cap_{}", capability_id.simple());

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("fake provider binds");
    let model_address = listener.local_addr().expect("fake provider address");
    let provider_state = Arc::new(ChildProviderState {
        request_count: AtomicUsize::new(0),
        model_tool_name,
        workflow_version_id,
    });
    let server = tokio::spawn(async move {
        axum::serve(
            listener,
            Router::new()
                .route("/v1/chat/completions", post(child_completion))
                .with_state(provider_state),
        )
        .await
        .expect("fake provider serves");
    });

    sqlx::query("insert into organizations (id, slug, name) values ($1, $2, 'Child Test')")
        .bind(organization_id)
        .bind(format!("child-{organization_id}"))
        .execute(&owner_pool)
        .await
        .expect("organization inserts");
    sqlx::query(
        "insert into workspaces (id, organization_id, slug, name)
         values ($1, $2, $3, 'Child Test')",
    )
    .bind(workspace_id)
    .bind(organization_id)
    .bind(format!("child-{workspace_id}"))
    .execute(&owner_pool)
    .await
    .expect("workspace inserts");
    sqlx::query(
        "insert into connections (
            id, organization_id, workspace_id, name, provider_kind, configuration
         ) values ($1, $2, $3, 'Child model', 'openai_compatible', $4)",
    )
    .bind(connection_id)
    .bind(organization_id)
    .bind(workspace_id)
    .bind(json!({ "api_key_secret_name": "api_key" }))
    .execute(&owner_pool)
    .await
    .expect("connection inserts");
    let cipher = Arc::new(
        LocalEnvelopeCipher::from_encoded("test-v1".to_owned(), &envelope_key)
            .expect("test envelope key is valid"),
    );
    let sealed = cipher
        .seal(
            b"test-provider-key",
            format!("connection/{connection_id}/api_key").as_bytes(),
        )
        .expect("provider key seals");
    sqlx::query(
        "insert into connection_secrets (
            organization_id, workspace_id, connection_id, secret_name,
            ciphertext, nonce, key_id
         ) values ($1, $2, $3, 'api_key', $4, $5, $6)",
    )
    .bind(organization_id)
    .bind(workspace_id)
    .bind(connection_id)
    .bind(sealed.ciphertext)
    .bind(sealed.nonce)
    .bind(sealed.key_id)
    .execute(&owner_pool)
    .await
    .expect("provider secret inserts");
    sqlx::query(
        "insert into model_profiles (
            id, organization_id, workspace_id, connection_id,
            name, base_url, model, configuration
         ) values ($1, $2, $3, $4, 'Child model', $5, 'fake-model', $6)",
    )
    .bind(model_profile_id)
    .bind(organization_id)
    .bind(workspace_id)
    .bind(connection_id)
    .bind(format!("http://{model_address}/v1"))
    .bind(json!({ "timeout_seconds": 5 }))
    .execute(&owner_pool)
    .await
    .expect("model profile inserts");
    sqlx::query(
        "insert into capability_definitions (
            id, organization_id, registry_key, display_name, description,
            input_schema, output_schema, idempotency_mode, risk_level, executor_key
         ) values ($1, $2, 'zeus.child-run', 'Child Run', 'Starts one child Run',
                   $3, $4, 'required', 'medium', 'builtin.child_run')",
    )
    .bind(capability_id)
    .bind(organization_id)
    .bind(json!({
        "type": "object",
        "required": ["workflow_version_id", "task", "token_budget", "max_runtime_seconds"],
        "properties": {
            "workflow_version_id": { "type": "string", "format": "uuid" },
            "task": { "type": "string" },
            "token_budget": { "type": "integer", "minimum": 1 },
            "max_runtime_seconds": { "type": "integer", "minimum": 1 }
        },
        "additionalProperties": false
    }))
    .bind(json!({ "type": "object" }))
    .execute(&owner_pool)
    .await
    .expect("child capability inserts");
    sqlx::query(
        "insert into workspace_capabilities (organization_id, workspace_id, capability_id)
         values ($1, $2, $3)",
    )
    .bind(organization_id)
    .bind(workspace_id)
    .bind(capability_id)
    .execute(&owner_pool)
    .await
    .expect("workspace capability inserts");
    sqlx::query(
        "insert into agents (id, organization_id, workspace_id, name)
         values ($1, $2, $3, 'Child agent')",
    )
    .bind(agent_id)
    .bind(organization_id)
    .bind(workspace_id)
    .execute(&owner_pool)
    .await
    .expect("agent inserts");
    sqlx::query(
        "insert into agent_versions (
            id, organization_id, workspace_id, agent_id, version_number, instructions
         ) values ($1, $2, $3, $4, 1, 'Delegate only when requested.')",
    )
    .bind(agent_version_id)
    .bind(organization_id)
    .bind(workspace_id)
    .bind(agent_id)
    .execute(&owner_pool)
    .await
    .expect("agent version inserts");
    sqlx::query(
        "insert into workflows (id, organization_id, workspace_id, name)
         values ($1, $2, $3, 'Child workflow')",
    )
    .bind(workflow_id)
    .bind(organization_id)
    .bind(workspace_id)
    .execute(&owner_pool)
    .await
    .expect("workflow inserts");
    sqlx::query(
        "insert into workflow_versions (
            id, organization_id, workspace_id, workflow_id, version_number,
            agent_version_id, model_profile_id, input_schema, output_schema,
            capability_policy, token_budget, max_runtime_seconds
         ) values ($1, $2, $3, $4, 1, $5, $6, '{}'::jsonb, '{}'::jsonb, $7, 1000, 900)",
    )
    .bind(workflow_version_id)
    .bind(organization_id)
    .bind(workspace_id)
    .bind(workflow_id)
    .bind(agent_version_id)
    .bind(model_profile_id)
    .bind(json!({ "allowed": ["zeus.child-run"] }))
    .execute(&owner_pool)
    .await
    .expect("workflow version inserts");
    sqlx::query(
        "insert into sessions (id, organization_id, workspace_id, title)
         values ($1, $2, $3, 'Parent session')",
    )
    .bind(parent_session_id)
    .bind(organization_id)
    .bind(workspace_id)
    .execute(&owner_pool)
    .await
    .expect("parent session inserts");
    sqlx::query(
        "insert into runs (
            id, organization_id, workspace_id, workflow_version_id,
            session_id, idempotency_key
         ) values ($1, $2, $3, $4, $5, $6)",
    )
    .bind(parent_run_id)
    .bind(organization_id)
    .bind(workspace_id)
    .bind(workflow_version_id)
    .bind(parent_session_id)
    .bind(format!("child-parent-{parent_run_id}"))
    .execute(&owner_pool)
    .await
    .expect("parent run inserts");
    sqlx::query(
        "select * from zeus_private.append_session_event(
            $1, 'user_message', 'system', null, $2, $3
         )",
    )
    .bind(parent_session_id)
    .bind(json!({ "content": "parent task" }))
    .bind(parent_run_id)
    .execute(&owner_pool)
    .await
    .expect("parent message appends");

    let runtime_pool = connect_pool_as_role(&database_url, 5, RUNTIME_DATABASE_ROLE)
        .await
        .expect("runtime role connects");
    let envelope: Arc<dyn EnvelopeCipher> = cipher;
    let executor =
        DurableRunExecutor::new(runtime_pool.clone(), "child-test-node".to_owned(), envelope);

    let first_parent = claim(&runtime_pool).await;
    assert_eq!(first_parent.run_id, parent_run_id);
    let first_outcome = executor
        .execute(&first_parent, CancellationToken::new())
        .await;
    assert!(
        matches!(&first_outcome, RunOutcome::WaitingChild),
        "parent returned unexpected outcome: {first_outcome:?}"
    );
    finish(&runtime_pool, &first_parent, "waiting_child", None).await;

    let (child_run_id, child_session_id, token_budget, runtime_budget, child_status): (
        Uuid,
        Uuid,
        Option<i64>,
        Option<i32>,
        String,
    ) = sqlx::query_as(
        "select id, session_id, token_budget_override, max_runtime_seconds_override, status
         from runs where parent_run_id = $1",
    )
    .bind(parent_run_id)
    .fetch_one(&owner_pool)
    .await
    .expect("child run reads");
    assert_ne!(child_session_id, parent_session_id);
    assert_eq!(token_budget, Some(200));
    assert_eq!(runtime_budget, Some(120));
    assert_eq!(child_status, "queued");

    let child = claim(&runtime_pool).await;
    assert_eq!(child.run_id, child_run_id);
    let child_output = match executor.execute(&child, CancellationToken::new()).await {
        RunOutcome::Succeeded(output) => output,
        outcome => panic!("child returned unexpected outcome: {outcome:?}"),
    };
    assert_eq!(child_output, json!({ "content": "child complete" }));
    finish(&runtime_pool, &child, "succeeded", Some(child_output)).await;

    let parent_status: String = sqlx::query_scalar("select status from runs where id = $1")
        .bind(parent_run_id)
        .fetch_one(&owner_pool)
        .await
        .expect("parent status reads");
    assert_eq!(parent_status, "queued");

    let resumed_parent = claim(&runtime_pool).await;
    assert_eq!(resumed_parent.run_id, parent_run_id);
    let parent_output = match executor
        .execute(&resumed_parent, CancellationToken::new())
        .await
    {
        RunOutcome::Succeeded(output) => output,
        outcome => panic!("resumed parent returned unexpected outcome: {outcome:?}"),
    };
    assert_eq!(parent_output, json!({ "content": "parent complete" }));
    finish(
        &runtime_pool,
        &resumed_parent,
        "succeeded",
        Some(parent_output),
    )
    .await;

    let facts: (String, String, i64, i64) = sqlx::query_as(
        "select parent.status, tool.status,
                (select count(*)::bigint from run_links where parent_run_id = parent.id and relation = 'child'),
                (select count(*)::bigint from session_events where run_id = parent.id and event_type = 'tool_result')
         from runs parent
         join tool_calls tool on tool.run_id = parent.id
         where parent.id = $1",
    )
    .bind(parent_run_id)
    .fetch_one(&owner_pool)
    .await
    .expect("durable child facts read");
    assert_eq!(
        facts,
        ("succeeded".to_owned(), "succeeded".to_owned(), 1, 1)
    );
    server.abort();
}

async fn claim(pool: &sqlx::PgPool) -> ClaimedRun {
    sqlx::query_as("select * from zeus_private.claim_run('child-test-node', 30)")
        .fetch_one(pool)
        .await
        .expect("run claims")
}

async fn finish(pool: &sqlx::PgPool, run: &ClaimedRun, status: &str, output: Option<Value>) {
    let committed: bool = sqlx::query_scalar(
        "select zeus_private.finish_run($1, 'child-test-node', $2, $3, $4, null, null)",
    )
    .bind(run.run_id)
    .bind(run.fence_token)
    .bind(status)
    .bind(output)
    .fetch_one(pool)
    .await
    .expect("run outcome commits");
    assert!(committed);
}

struct ChildProviderState {
    request_count: AtomicUsize,
    model_tool_name: String,
    workflow_version_id: Uuid,
}

async fn child_completion(
    State(state): State<Arc<ChildProviderState>>,
    Json(request): Json<Value>,
) -> Response {
    let request_number = state.request_count.fetch_add(1, Ordering::SeqCst);
    let messages = request
        .get("messages")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let has_tool_result = messages
        .iter()
        .any(|message| message.get("role").and_then(Value::as_str) == Some("tool"));
    let is_child = messages.iter().any(|message| {
        message.get("role").and_then(Value::as_str) == Some("user")
            && message.get("content").and_then(Value::as_str) == Some("child task")
    });
    let body = if has_tool_result {
        final_stream("parent complete")
    } else if is_child {
        final_stream("child complete")
    } else {
        let arguments = json!({
            "workflow_version_id": state.workflow_version_id,
            "task": "child task",
            "token_budget": 200,
            "max_runtime_seconds": 120,
        });
        let tool_chunk = json!({
            "choices": [{
                "index": 0,
                "delta": {
                    "tool_calls": [{
                        "index": 0,
                        "id": "call_child",
                        "function": {
                            "name": state.model_tool_name,
                            "arguments": arguments.to_string(),
                        }
                    }]
                }
            }]
        });
        format!(
            "data: {tool_chunk}\n\ndata: {{\"choices\":[],\"usage\":{{\"prompt_tokens\":5,\"completion_tokens\":1}}}}\n\ndata: [DONE]\n\n"
        )
    };
    let mut response = Response::new(body.into());
    *response.status_mut() = StatusCode::OK;
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/event-stream"),
    );
    response.headers_mut().insert(
        "x-request-id",
        HeaderValue::from_str(&format!("child-test-request-{request_number}"))
            .expect("request id is valid"),
    );
    response
}

fn final_stream(content: &str) -> String {
    let chunk = json!({ "choices": [{ "index": 0, "delta": { "content": content } }] });
    format!(
        "data: {chunk}\n\ndata: {{\"choices\":[],\"usage\":{{\"prompt_tokens\":3,\"completion_tokens\":2}}}}\n\ndata: [DONE]\n\n"
    )
}
