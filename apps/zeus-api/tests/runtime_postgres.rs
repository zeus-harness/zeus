use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use axum::{Json, Router, extract::State, response::Response, routing::post};
use http::{HeaderValue, StatusCode, header};
use secrecy::SecretString;
use serde_json::json;
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
#[allow(clippy::too_many_lines)] // One end-to-end flow verifies the durable runtime event sequence.
async fn durable_runtime_persists_tool_pair_final_message_and_usage() {
    let database_url = std::env::var("ZEUS_TEST_DATABASE_URL")
        .expect("ZEUS_TEST_DATABASE_URL is required for this ignored test");
    let envelope_key = SecretString::from(
        std::env::var("ZEUS_TEST_ENVELOPE_KEY")
            .expect("ZEUS_TEST_ENVELOPE_KEY is required for this ignored test"),
    );
    let pool = connect_pool(&database_url, 5)
        .await
        .expect("test database connects");
    migrate(&pool).await.expect("test database migrates");

    let capability_id = Uuid::now_v7();
    let capability_registry_key = "test.echo".to_owned();
    let model_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("fake provider binds");
    let model_address = model_listener.local_addr().expect("fake provider address");
    let provider_state = Arc::new(FakeProviderState {
        request_count: AtomicUsize::new(0),
        model_tool_name: format!("cap_{}", capability_id.simple()),
    });
    let model_server = tokio::spawn(async move {
        axum::serve(
            model_listener,
            Router::new()
                .route("/v1/chat/completions", post(fake_completion))
                .with_state(provider_state),
        )
        .await
        .expect("fake provider serves");
    });

    let organization_id = Uuid::now_v7();
    let workspace_id = Uuid::now_v7();
    let connection_id = Uuid::now_v7();
    let model_profile_id = Uuid::now_v7();
    let agent_id = Uuid::now_v7();
    let agent_version_id = Uuid::now_v7();
    let workflow_id = Uuid::now_v7();
    let workflow_version_id = Uuid::now_v7();
    let session_id = Uuid::now_v7();
    let run_id = Uuid::now_v7();

    sqlx::query("insert into organizations (id, slug, name) values ($1, $2, 'Runtime Test')")
        .bind(organization_id)
        .bind(format!("runtime-{organization_id}"))
        .execute(&pool)
        .await
        .expect("organization inserts");
    sqlx::query(
        "insert into workspaces (id, organization_id, slug, name)
         values ($1, $2, $3, 'Runtime Test')",
    )
    .bind(workspace_id)
    .bind(organization_id)
    .bind(format!("runtime-{workspace_id}"))
    .execute(&pool)
    .await
    .expect("workspace inserts");
    sqlx::query(
        "insert into connections (
            id, organization_id, workspace_id, name, provider_kind, configuration
         ) values ($1, $2, $3, 'Runtime model', 'openai_compatible', $4)",
    )
    .bind(connection_id)
    .bind(organization_id)
    .bind(workspace_id)
    .bind(json!({ "api_key_secret_name": "api_key" }))
    .execute(&pool)
    .await
    .expect("connection inserts");

    let cipher = Arc::new(
        LocalEnvelopeCipher::from_encoded("test-v1".to_owned(), &envelope_key)
            .expect("test envelope key is valid"),
    );
    let aad = format!("connection/{connection_id}/api_key");
    let sealed = cipher
        .seal(b"test-provider-key", aad.as_bytes())
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
    .execute(&pool)
    .await
    .expect("provider secret inserts");
    sqlx::query(
        "insert into model_profiles (
            id, organization_id, workspace_id, connection_id,
            name, base_url, model, configuration
         ) values ($1, $2, $3, $4, 'Runtime model', $5, 'fake-model', $6)",
    )
    .bind(model_profile_id)
    .bind(organization_id)
    .bind(workspace_id)
    .bind(connection_id)
    .bind(format!("http://{model_address}/v1"))
    .bind(json!({ "timeout_seconds": 5 }))
    .execute(&pool)
    .await
    .expect("model profile inserts");
    sqlx::query(
        "insert into capability_definitions (
            id, organization_id, registry_key, display_name, description,
            input_schema, output_schema, idempotency_mode, risk_level, executor_key
         ) values ($1, $2, $3, 'Echo', 'Echoes validated input',
                   $4, '{}'::jsonb, 'supported', 'low', 'builtin.echo')",
    )
    .bind(capability_id)
    .bind(organization_id)
    .bind(&capability_registry_key)
    .bind(json!({
        "type": "object",
        "properties": { "message": { "type": "string" } },
        "required": ["message"],
    }))
    .execute(&pool)
    .await
    .expect("capability definition inserts");
    sqlx::query(
        "insert into workspace_capabilities (
            organization_id, workspace_id, capability_id
         ) values ($1, $2, $3)",
    )
    .bind(organization_id)
    .bind(workspace_id)
    .bind(capability_id)
    .execute(&pool)
    .await
    .expect("workspace capability inserts");
    sqlx::query(
        "insert into agents (id, organization_id, workspace_id, name)
         values ($1, $2, $3, 'Runtime agent')",
    )
    .bind(agent_id)
    .bind(organization_id)
    .bind(workspace_id)
    .execute(&pool)
    .await
    .expect("agent inserts");
    sqlx::query(
        "insert into agent_versions (
            id, organization_id, workspace_id, agent_id, version_number, instructions
         ) values ($1, $2, $3, $4, 1, 'Reply briefly.')",
    )
    .bind(agent_version_id)
    .bind(organization_id)
    .bind(workspace_id)
    .bind(agent_id)
    .execute(&pool)
    .await
    .expect("agent version inserts");
    sqlx::query(
        "insert into workflows (id, organization_id, workspace_id, name)
         values ($1, $2, $3, 'Runtime workflow')",
    )
    .bind(workflow_id)
    .bind(organization_id)
    .bind(workspace_id)
    .execute(&pool)
    .await
    .expect("workflow inserts");
    sqlx::query(
        "insert into workflow_versions (
            id, organization_id, workspace_id, workflow_id, version_number,
            agent_version_id, model_profile_id, input_schema, output_schema,
            capability_policy
         ) values ($1, $2, $3, $4, 1, $5, $6, '{}'::jsonb, '{}'::jsonb, $7)",
    )
    .bind(workflow_version_id)
    .bind(organization_id)
    .bind(workspace_id)
    .bind(workflow_id)
    .bind(agent_version_id)
    .bind(model_profile_id)
    .bind(json!({ "allowed": [capability_registry_key] }))
    .execute(&pool)
    .await
    .expect("workflow version inserts");
    sqlx::query(
        "insert into sessions (id, organization_id, workspace_id, title)
         values ($1, $2, $3, 'Runtime session')",
    )
    .bind(session_id)
    .bind(organization_id)
    .bind(workspace_id)
    .execute(&pool)
    .await
    .expect("session inserts");
    sqlx::query(
        "insert into runs (
            id, organization_id, workspace_id, workflow_version_id,
            session_id, idempotency_key
         ) values ($1, $2, $3, $4, $5, $6)",
    )
    .bind(run_id)
    .bind(organization_id)
    .bind(workspace_id)
    .bind(workflow_version_id)
    .bind(session_id)
    .bind(format!("runtime-test-{run_id}"))
    .execute(&pool)
    .await
    .expect("run inserts");
    sqlx::query(
        "select * from zeus_private.append_session_event(
            $1, 'user_message', 'system', null, $2, $3
         )",
    )
    .bind(session_id)
    .bind(json!({ "content": "Say hello." }))
    .bind(run_id)
    .execute(&pool)
    .await
    .expect("user message appends");

    let runtime_pool = connect_pool_as_role(&database_url, 3, RUNTIME_DATABASE_ROLE)
        .await
        .expect("runtime role database connects");
    let current_role: String = sqlx::query_scalar("select current_user")
        .fetch_one(&runtime_pool)
        .await
        .expect("runtime role can query its identity");
    assert_eq!(current_role, RUNTIME_DATABASE_ROLE);
    let claimed = sqlx::query_as::<_, ClaimedRun>(
        "select * from zeus_private.claim_run('runtime-test-node', 30)",
    )
    .fetch_one(&runtime_pool)
    .await
    .expect("run claims");
    assert_eq!(claimed.run_id, run_id);
    let envelope: Arc<dyn EnvelopeCipher> = cipher;
    let executor = DurableRunExecutor::new(runtime_pool, "runtime-test-node".to_owned(), envelope);
    let outcome = executor.execute(&claimed, CancellationToken::new()).await;
    assert!(matches!(
        outcome,
        RunOutcome::Succeeded(ref output) if output == &json!({ "content": "Hello from Zeus." })
    ));

    let assistant_count: i64 = sqlx::query_scalar(
        "select count(*)::bigint from session_events
         where run_id = $1 and event_type = 'assistant_message'
           and payload ->> 'content' = 'Hello from Zeus.'",
    )
    .bind(run_id)
    .fetch_one(&pool)
    .await
    .expect("assistant count reads");
    let usage: (i64, i64, i64) = sqlx::query_as(
        "select coalesce(sum(prompt_tokens), 0)::bigint,
                coalesce(sum(completion_tokens), 0)::bigint,
                count(*)::bigint
         from run_usage where run_id = $1",
    )
    .bind(run_id)
    .fetch_one(&pool)
    .await
    .expect("usage reads");
    let final_count: i64 = sqlx::query_scalar(
        "select count(*)::bigint from run_events
         where run_id = $1 and event_type = 'model.final'",
    )
    .bind(run_id)
    .fetch_one(&pool)
    .await
    .expect("final event count reads");
    let tool_pair: (i64, i64, i64) = sqlx::query_as(
        "select
           count(*) filter (where event_type = 'tool_call')::bigint,
           count(*) filter (where event_type = 'tool_result')::bigint,
           count(*) filter (
             where event_type = 'tool_result'
               and payload -> 'result' -> 'echo' ->> 'message' = 'hello'
           )::bigint
         from session_events where run_id = $1",
    )
    .bind(run_id)
    .fetch_one(&pool)
    .await
    .expect("tool pair reads");
    assert_eq!(assistant_count, 1);
    assert_eq!(usage, (8, 5, 2));
    assert_eq!(final_count, 1);
    assert_eq!(tool_pair, (1, 1, 1));

    model_server.abort();
}

struct FakeProviderState {
    request_count: AtomicUsize,
    model_tool_name: String,
}

async fn fake_completion(
    State(state): State<Arc<FakeProviderState>>,
    Json(request): Json<serde_json::Value>,
) -> Response {
    let request_number = state.request_count.fetch_add(1, Ordering::SeqCst);
    let body = if request_number == 0 {
        let tool_chunk = json!({
            "choices": [{
                "index": 0,
                "delta": {
                    "tool_calls": [{
                        "index": 0,
                        "id": "call_echo",
                        "function": {
                            "name": state.model_tool_name,
                            "arguments": "{\"message\":\"hello\"}",
                        },
                    }],
                },
            }],
        });
        let usage = json!({
            "choices": [],
            "usage": { "prompt_tokens": 5, "completion_tokens": 1 },
        });
        format!("data: {tool_chunk}\n\ndata: {usage}\n\ndata: [DONE]\n\n")
    } else {
        let has_tool_result = request
            .get("messages")
            .and_then(serde_json::Value::as_array)
            .is_some_and(|messages| {
                messages.iter().any(|message| {
                    message.get("role").and_then(serde_json::Value::as_str) == Some("tool")
                })
            });
        if !has_tool_result {
            let mut response = Response::new("missing tool result".into());
            *response.status_mut() = StatusCode::UNPROCESSABLE_ENTITY;
            return response;
        }
        concat!(
            "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"Hello from \"}}]}\n\n",
            "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"Zeus.\"}}]}\n\n",
            "data: {\"choices\":[],\"usage\":{\"prompt_tokens\":3,\"completion_tokens\":4}}\n\n",
            "data: [DONE]\n\n",
        )
        .to_owned()
    };
    let mut response = Response::new(body.into());
    *response.status_mut() = StatusCode::OK;
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/event-stream"),
    );
    response.headers_mut().insert(
        "x-request-id",
        HeaderValue::from_str(&format!("runtime-smoke-request-{request_number}"))
            .expect("request id header is valid"),
    );
    response
}
