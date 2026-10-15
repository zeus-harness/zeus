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
    let read_capability_id = Uuid::now_v7();
    let work_item_id = Uuid::now_v7();
    let other_work_item_id = Uuid::now_v7();
    let capability_registry_key = "test.echo".to_owned();
    let model_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("fake provider binds");
    let model_address = model_listener.local_addr().expect("fake provider address");
    let provider_state = Arc::new(FakeProviderState {
        request_count: AtomicUsize::new(0),
        model_tool_name: format!("cap_{}", capability_id.simple()),
        read_tool_name: format!("cap_{}", read_capability_id.simple()),
        other_work_item_id,
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
    let owner_user_id = Uuid::now_v7();

    sqlx::query(
        "insert into organizations (id, slug, name, status)
         values ($1, $2, 'Runtime Test', 'provisioning')",
    )
    .bind(organization_id)
    .bind(format!("runtime-{organization_id}"))
    .execute(&pool)
    .await
    .expect("organization inserts");
    sqlx::query("insert into organization_governance (organization_id) values ($1)")
        .bind(organization_id)
        .execute(&pool)
        .await
        .expect("organization governance inserts");
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
        "insert into users (id, email, display_name, status, email_verified_at)
         values ($1, $2, 'Runtime Owner', 'active', now())",
    )
    .bind(owner_user_id)
    .bind(format!("runtime-owner-{owner_user_id}@example.test"))
    .execute(&pool)
    .await
    .expect("runtime owner inserts");
    sqlx::query(
        "insert into organization_memberships (organization_id, user_id, role, status)
         values ($1, $2, 'owner', 'active')",
    )
    .bind(organization_id)
    .bind(owner_user_id)
    .execute(&pool)
    .await
    .expect("runtime organization owner membership inserts");
    sqlx::query(
        "insert into workspace_memberships (
           organization_id, workspace_id, user_id, role, status
         ) values ($1, $2, $3, 'owner', 'active')",
    )
    .bind(organization_id)
    .bind(workspace_id)
    .bind(owner_user_id)
    .execute(&pool)
    .await
    .expect("runtime workspace owner membership inserts");
    sqlx::query("update organizations set status = 'active' where id = $1")
        .bind(organization_id)
        .execute(&pool)
        .await
        .expect("runtime organization activates");
    sqlx::query(
        "insert into connections (
            id, organization_id, workspace_id, name, provider_kind, configuration
         ) values ($1, $2, $3, 'Runtime model', 'openai_compatible', $4)",
    )
    .bind(connection_id)
    .bind(organization_id)
    .bind(Option::<Uuid>::None)
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
    .bind(Option::<Uuid>::None)
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
    .bind(Option::<Uuid>::None)
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
        "insert into capability_definitions (
            id, organization_id, registry_key, display_name, description,
            input_schema, output_schema, idempotency_mode, risk_level, executor_key
         ) values ($1, $2, 'zeus.work-item-read', 'Current WorkItem', 'Read the linked WorkItem',
                   '{}'::jsonb, '{}'::jsonb, 'supported', 'low', 'builtin.work_item_read')",
    )
    .bind(read_capability_id)
    .bind(organization_id)
    .execute(&pool)
    .await
    .expect("read capability inserts with deliberately permissive catalog schema");
    sqlx::query(
        "insert into workspace_capabilities (organization_id, workspace_id, capability_id)
         values ($1, $2, $3)",
    )
    .bind(organization_id)
    .bind(workspace_id)
    .bind(read_capability_id)
    .execute(&pool)
    .await
    .expect("read capability enables");
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
    .bind(json!({ "allowed": [capability_registry_key, "zeus.work-item-read"] }))
    .execute(&pool)
    .await
    .expect("workflow version inserts");
    sqlx::query(
        "insert into work_items (id, organization_id, workspace_id, title, description, input)
         values ($1, $2, $3, 'Linked task', 'The current task', '{\"topic\":\"invoicing\"}'::jsonb),
                ($4, $2, $3, 'Unrelated task', 'Must not reach the model', '{}'::jsonb)",
    )
    .bind(work_item_id)
    .bind(organization_id)
    .bind(workspace_id)
    .bind(other_work_item_id)
    .execute(&pool)
    .await
    .expect("linked and unrelated work items insert");
    sqlx::query(
        "insert into sessions (id, organization_id, workspace_id, title, work_item_id)
         values ($1, $2, $3, 'Runtime session', $4)",
    )
    .bind(session_id)
    .bind(organization_id)
    .bind(workspace_id)
    .bind(work_item_id)
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
    let executor = DurableRunExecutor::new(
        runtime_pool.clone(),
        "runtime-test-node".to_owned(),
        envelope.clone(),
    );
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
    assert_eq!(tool_pair, (3, 3, 1));
    let read_result: serde_json::Value = sqlx::query_scalar(
        "select payload -> 'result' from session_events
         where run_id = $1 and event_type = 'tool_result'
           and payload -> 'result' ->> 'title' = 'Linked task'",
    )
    .bind(run_id)
    .fetch_one(&pool)
    .await
    .expect("current work item reaches the persistent tool result");
    assert_eq!(read_result["id"], work_item_id.to_string());
    assert_eq!(read_result["input"]["topic"], "invoicing");
    let denied: i64 = sqlx::query_scalar(
        "select count(*) from tool_calls
         where run_id = $1 and error_code = 'capability_input_schema_violation'",
    )
    .bind(run_id)
    .fetch_one(&pool)
    .await
    .expect("arbitrary work item selection is rejected");
    assert_eq!(denied, 1);
    let leaked: bool = sqlx::query_scalar(
        "select exists(select 1 from session_events
         where run_id = $1 and event_type = 'tool_result'
           and payload::text like '%Must not reach the model%')",
    )
    .bind(run_id)
    .fetch_one(&pool)
    .await
    .expect("unrelated content remains absent");
    assert!(!leaked);

    // Accelerated outage scenario: preserve the original start time over a three-day gap.
    let finished: bool = sqlx::query_scalar(
        "select zeus_private.finish_run($1, 'runtime-test-node', $2, 'succeeded', '{}', null, null)",
    )
    .bind(run_id)
    .bind(claimed.fence_token)
    .fetch_one(&runtime_pool)
    .await
    .expect("original run finishes");
    assert!(finished);
    let aged_id = Uuid::now_v7();
    sqlx::query(
        "insert into runs (id, organization_id, workspace_id, workflow_version_id,
                           session_id, idempotency_key, started_at)
         values ($1, $2, $3, $4, $5, $6, now() - interval '3 days')",
    )
    .bind(aged_id)
    .bind(organization_id)
    .bind(workspace_id)
    .bind(workflow_version_id)
    .bind(session_id)
    .bind(format!("aged-runtime-{aged_id}"))
    .execute(&pool)
    .await
    .expect("aged run inserts");
    let old_claim =
        sqlx::query_as::<_, ClaimedRun>("select * from zeus_private.claim_run('old-node', 30)")
            .fetch_one(&runtime_pool)
            .await
            .expect("old node claims");
    assert_eq!(old_claim.run_id, aged_id);
    sqlx::query("update runs set lease_expires_at = now() - interval '3 days' where id = $1")
        .bind(aged_id)
        .execute(&pool)
        .await
        .expect("simulate prolonged executor outage");
    let recovered = sqlx::query_as::<_, ClaimedRun>(
        "select * from zeus_private.claim_run('replacement-node', 30)",
    )
    .fetch_one(&runtime_pool)
    .await
    .expect("replacement node reclaims");
    assert_eq!(recovered.run_id, aged_id);
    assert!(recovered.fence_token > old_claim.fence_token);
    assert_eq!(recovered.attempt_number, old_claim.attempt_number + 1);
    let stale_heartbeat: bool =
        sqlx::query_scalar("select zeus_private.heartbeat_run($1, 'old-node', $2, 30)")
            .bind(aged_id)
            .bind(old_claim.fence_token)
            .fetch_one(&runtime_pool)
            .await
            .expect("stale heartbeat returns a decision");
    assert!(!stale_heartbeat);
    let stale_finish: bool = sqlx::query_scalar(
        "select zeus_private.finish_run($1, 'old-node', $2, 'succeeded', '{}', null, null)",
    )
    .bind(aged_id)
    .bind(old_claim.fence_token)
    .fetch_one(&runtime_pool)
    .await
    .expect("stale completion returns a decision");
    assert!(!stale_finish);
    let recovered_executor = DurableRunExecutor::new(
        runtime_pool.clone(),
        "replacement-node".to_owned(),
        envelope.clone(),
    );
    let expired = recovered_executor
        .execute(&recovered, CancellationToken::new())
        .await;
    assert!(matches!(expired, RunOutcome::Failed { ref code, .. } if code == "run_timeout"));
    let preserved_age: bool =
        sqlx::query_scalar("select started_at < now() - interval '2 days' from runs where id = $1")
            .bind(aged_id)
            .fetch_one(&pool)
            .await
            .expect("original runtime budget survives reclaim");
    assert!(preserved_age);
    let committed: bool = sqlx::query_scalar(
        "select zeus_private.finish_run($1, 'replacement-node', $2, 'failed', null, 'run_timeout', 'budget elapsed')",
    )
    .bind(aged_id)
    .bind(recovered.fence_token)
    .fetch_one(&runtime_pool)
    .await
    .expect("replacement commits timeout");
    assert!(committed);
    let persisted: (String, Option<String>) =
        sqlx::query_as("select status, error_code from runs where id = $1")
            .bind(aged_id)
            .fetch_one(&pool)
            .await
            .expect("terminal timeout reads");
    assert_eq!(
        persisted,
        ("failed".to_owned(), Some("run_timeout".to_owned()))
    );

    verify_resource_approval_request(
        &pool,
        &runtime_pool,
        workflow_version_id,
        capability_id,
        owner_user_id,
        envelope.clone(),
    )
    .await;
    verify_studio_creation(
        &pool,
        &runtime_pool,
        workflow_version_id,
        session_id,
        owner_user_id,
    )
    .await;
    verify_reusable_durable_policy(
        &pool,
        &runtime_pool,
        workflow_version_id,
        session_id,
        capability_id,
        organization_id,
        workspace_id,
    )
    .await;
    verify_model_configuration_binding(
        &pool,
        &runtime_pool,
        workflow_version_id,
        session_id,
        envelope.clone(),
    )
    .await;
    verify_code_checkpoints(
        &pool,
        &runtime_pool,
        workflow_version_id,
        session_id,
        organization_id,
        workspace_id,
        envelope,
    )
    .await;
    model_server.abort();
}

async fn verify_model_configuration_binding(
    pool: &sqlx::PgPool,
    runtime: &sqlx::PgPool,
    version: Uuid,
    session: Uuid,
    envelope: Arc<dyn EnvelopeCipher>,
) {
    let run = Uuid::now_v7();
    let (org, workspace, profile): (Uuid, Uuid, Uuid) = sqlx::query_as(
        "select organization_id,workspace_id,model_profile_id from workflow_versions where id=$1",
    )
    .bind(version)
    .fetch_one(pool)
    .await
    .unwrap();
    let original: (serde_json::Value, i64) =
        sqlx::query_as("select configuration,revision from model_profiles where id=$1")
            .bind(profile)
            .fetch_one(pool)
            .await
            .unwrap();
    sqlx::query("insert into runs(id,organization_id,workspace_id,workflow_version_id,session_id,idempotency_key,status,lease_owner,fence_token,lease_expires_at,started_at) values($1,$2,$3,$4,$5,$1::text,'running','configuration-test',1,now()+interval '1 minute',now())")
        .bind(run).bind(org).bind(workspace).bind(version).bind(session).execute(pool).await.unwrap();
    sqlx::query("update model_profiles set revision=revision+1,configuration=jsonb_set(configuration,'{temperature}','0.55') where id=$1")
        .bind(profile).execute(pool).await.unwrap();
    let claimed = ClaimedRun {
        run_id: run,
        organization_id: org,
        workspace_id: workspace,
        session_id: session,
        workflow_version_id: version,
        fence_token: 1,
        attempt_number: 1,
    };
    // Recreate the executor to prove the binding is durable across process restart.
    for _ in 0..2 {
        let executor = DurableRunExecutor::new(
            runtime.clone(),
            "configuration-test".into(),
            envelope.clone(),
        );
        assert!(
            matches!(executor.execute(&claimed, CancellationToken::new()).await,
            RunOutcome::Failed { code, .. } if code == "runtime_configuration_unavailable")
        );
    }
    let started: i64 = sqlx::query_scalar(
        "select count(*) from run_events where run_id=$1 and event_type='runtime.started'",
    )
    .bind(run)
    .fetch_one(pool)
    .await
    .unwrap();
    assert_eq!(
        started, 0,
        "changed configuration fails before model, code or tool IO"
    );
    let bound_revision: i64 = sqlx::query_scalar(
        "select model_profile_revision from run_model_configuration_bindings where run_id=$1",
    )
    .bind(run)
    .fetch_one(pool)
    .await
    .unwrap();
    assert_eq!(bound_revision, original.1);
    sqlx::query("update model_profiles set revision=revision+1,configuration=$2 where id=$1")
        .bind(profile)
        .bind(original.0)
        .execute(pool)
        .await
        .unwrap();
    sqlx::query("update runs set status='failed',error_code='runtime_configuration_unavailable',finished_at=now(),lease_expires_at=null,lease_owner=null where id=$1")
        .bind(run).execute(pool).await.unwrap();
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
async fn verify_reusable_durable_policy(
    pool: &sqlx::PgPool,
    runtime: &sqlx::PgPool,
    original_version: Uuid,
    session: Uuid,
    capability: Uuid,
    organization: Uuid,
    workspace: Uuid,
) {
    let version = Uuid::now_v7();
    sqlx::query("insert into workflow_versions (id, organization_id, workspace_id, workflow_id,
        version_number, agent_version_id, model_profile_id, input_schema, output_schema, max_runtime_seconds, time_policy)
        select $1, organization_id, workspace_id, workflow_id, version_number + 1,
          agent_version_id, model_profile_id, input_schema, output_schema, 900,
          '{\"runtime_clock\":\"active\",\"wait_timeout_seconds\":604800,\"business_timeout_seconds\":2592000}'::jsonb
        from workflow_versions where id = $2")
        .bind(version).bind(original_version).execute(pool).await.expect("reusable version inserts");
    let first = Uuid::now_v7();
    let second = Uuid::now_v7();
    let expired = Uuid::now_v7();
    for (id, age) in [(first, 3), (second, 0), (expired, 31)] {
        sqlx::query("insert into runs (id, organization_id, workspace_id, workflow_version_id,
            session_id, idempotency_key, started_at, created_at)
            values ($1, $2, $3, $4, $5, $6, now() - make_interval(days => $7), now() - make_interval(days => $7))")
            .bind(id).bind(organization).bind(workspace).bind(version).bind(session)
            .bind(id.to_string()).bind(age).execute(pool).await.expect("independent run inserts");
    }
    let count: i32 = sqlx::query_scalar("select zeus_private.expire_run_waits(100)")
        .fetch_one(runtime)
        .await
        .expect("expired business deadline is swept");
    assert_eq!(count, 1);
    let status: String = sqlx::query_scalar("select status from runs where id = $1")
        .bind(expired)
        .fetch_one(pool)
        .await
        .unwrap();
    assert_eq!(status, "canceled");
    let claimed =
        sqlx::query_as::<_, ClaimedRun>("select * from zeus_private.claim_run('durable-test', 30)")
            .fetch_one(runtime)
            .await
            .unwrap();
    assert_eq!(claimed.run_id, first);
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    let heartbeat: bool =
        sqlx::query_scalar("select zeus_private.heartbeat_run($1,'durable-test',$2,30)")
            .bind(first)
            .bind(claimed.fence_token)
            .fetch_one(runtime)
            .await
            .unwrap();
    assert!(heartbeat);
    let remaining: i64 =
        sqlx::query_scalar("select 900000 - active_elapsed_ms from runs where id = $1")
            .bind(first)
            .fetch_one(pool)
            .await
            .unwrap();
    assert!(
        remaining > 890_000,
        "three calendar days do not consume active budget"
    );
    let tool = Uuid::now_v7();
    sqlx::query(
        "insert into tool_calls (id, organization_id, workspace_id, run_id, session_id,
        capability_id, call_key, fence_token, status, input)
        values ($1,$2,$3,$4,$5,$6,'durable-approval',$7,'pending_approval','{}')",
    )
    .bind(tool)
    .bind(organization)
    .bind(workspace)
    .bind(first)
    .bind(session)
    .bind(capability)
    .bind(claimed.fence_token)
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        "insert into approvals (organization_id, workspace_id, run_id, tool_call_id)
        values ($1,$2,$3,$4)",
    )
    .bind(organization)
    .bind(workspace)
    .bind(first)
    .bind(tool)
    .execute(pool)
    .await
    .unwrap();
    let released: bool = sqlx::query_scalar(
        "select zeus_private.finish_run($1,'durable-test',$2,'waiting_approval',null,null,null)",
    )
    .bind(first)
    .bind(claimed.fence_token)
    .fetch_one(runtime)
    .await
    .unwrap();
    assert!(released);
    let waiting: (String, bool, bool, i64) = sqlx::query_as(
        "select status, lease_owner is null,
        active_started_at is null, active_elapsed_ms from runs where id = $1",
    )
    .bind(first)
    .fetch_one(pool)
    .await
    .unwrap();
    assert_eq!(
        (&*waiting.0, waiting.1, waiting.2),
        ("waiting_approval", true, true)
    );
    let other =
        sqlx::query_as::<_, ClaimedRun>("select * from zeus_private.claim_run('other-run',30)")
            .fetch_one(runtime)
            .await
            .unwrap();
    assert_eq!(other.run_id, second, "waiting run is not claimed");
    let _: bool = sqlx::query_scalar(
        "select zeus_private.finish_run($1,'other-run',$2,'succeeded','{}',null,null)",
    )
    .bind(second)
    .bind(other.fence_token)
    .fetch_one(runtime)
    .await
    .unwrap();
    sqlx::query("update approvals set status = 'approved' where tool_call_id = $1")
        .bind(tool)
        .execute(pool)
        .await
        .unwrap();
    sqlx::query("update runs set status = 'queued', available_at = now() where id = $1")
        .bind(first)
        .execute(pool)
        .await
        .unwrap();
    let resumed =
        sqlx::query_as::<_, ClaimedRun>("select * from zeus_private.claim_run('resumed',30)")
            .fetch_one(runtime)
            .await
            .unwrap();
    assert_eq!(resumed.run_id, first);
    assert!(resumed.fence_token > claimed.fence_token);
    let elapsed: i64 = sqlx::query_scalar("select active_elapsed_ms from runs where id = $1")
        .bind(first)
        .fetch_one(pool)
        .await
        .unwrap();
    assert_eq!(
        elapsed, waiting.3,
        "waiting does not spend or reset execution budget"
    );
    // An approval resolved before the executor releases must not leave it asleep.
    let _: bool = sqlx::query_scalar(
        "select zeus_private.finish_run($1,'resumed',$2,'waiting_approval',null,null,null)",
    )
    .bind(first)
    .bind(resumed.fence_token)
    .fetch_one(runtime)
    .await
    .unwrap();
    let status: String = sqlx::query_scalar("select status from runs where id = $1")
        .bind(first)
        .fetch_one(pool)
        .await
        .unwrap();
    assert_eq!(status, "queued");
    sqlx::query("update approvals set status = 'pending', expires_at = now() - interval '2 days' where tool_call_id = $1")
        .bind(tool).execute(pool).await.unwrap();
    let count: i32 = sqlx::query_scalar("select zeus_private.expire_run_waits(100)")
        .fetch_one(runtime)
        .await
        .unwrap();
    assert_eq!(count, 1);
    let count: i32 = sqlx::query_scalar("select zeus_private.expire_run_waits(100)")
        .fetch_one(runtime)
        .await
        .unwrap();
    assert_eq!(count, 0, "expiry is idempotent");
    let statuses: (String, String) = sqlx::query_as(
        "select r.status, a.status from runs r
        join approvals a on a.run_id = r.id where r.id = $1",
    )
    .bind(first)
    .fetch_one(pool)
    .await
    .unwrap();
    assert_eq!(statuses, ("canceled".into(), "expired".into()));
    let state: (i64, bool) = sqlx::query_as(
        "select count(*), bool_and(workflow_version_id = $1)
        from runs where id = any($2)",
    )
    .bind(version)
    .bind(vec![first, second, expired])
    .fetch_one(pool)
    .await
    .unwrap();
    assert_eq!(state, (3, true));
    // Cancellation requested while alive must also finish if that executor dies.
    let orphan = Uuid::now_v7();
    sqlx::query(
        "insert into runs (id, organization_id, workspace_id, workflow_version_id,
        session_id, idempotency_key) values ($1,$2,$3,$4,$5,$6)",
    )
    .bind(orphan)
    .bind(organization)
    .bind(workspace)
    .bind(version)
    .bind(session)
    .bind(orphan.to_string())
    .execute(pool)
    .await
    .unwrap();
    let orphan_claim =
        sqlx::query_as::<_, ClaimedRun>("select * from zeus_private.claim_run('lost-executor',30)")
            .fetch_one(runtime)
            .await
            .unwrap();
    assert_eq!(orphan_claim.run_id, orphan);
    let _: bool = sqlx::query_scalar("select zeus_private.request_run_cancel($1)")
        .bind(orphan)
        .fetch_one(pool)
        .await
        .unwrap();
    sqlx::query("update runs set lease_expires_at = now() - interval '2 days' where id = $1")
        .bind(orphan)
        .execute(pool)
        .await
        .unwrap();
    let renewed: bool =
        sqlx::query_scalar("select zeus_private.heartbeat_run($1,'lost-executor',$2,30)")
            .bind(orphan)
            .bind(orphan_claim.fence_token)
            .fetch_one(runtime)
            .await
            .unwrap();
    assert!(!renewed, "expired leases cannot resurrect an executor");
    let count: i32 = sqlx::query_scalar("select zeus_private.expire_run_waits(100)")
        .fetch_one(runtime)
        .await
        .unwrap();
    assert_eq!(count, 1);
    let status: String = sqlx::query_scalar("select status from runs where id = $1")
        .bind(orphan)
        .fetch_one(pool)
        .await
        .unwrap();
    assert_eq!(status, "canceled");
    let finished: bool = sqlx::query_scalar(
        "select zeus_private.finish_run($1,'lost-executor',$2,'succeeded','{}',null,null)",
    )
    .bind(orphan)
    .bind(orphan_claim.fence_token)
    .fetch_one(runtime)
    .await
    .unwrap();
    assert!(!finished);
}

struct FakeProviderState {
    request_count: AtomicUsize,
    model_tool_name: String,
    read_tool_name: String,
    other_work_item_id: Uuid,
}

async fn fake_completion(
    State(state): State<Arc<FakeProviderState>>,
    Json(request): Json<serde_json::Value>,
) -> Response {
    let request_number = state.request_count.fetch_add(1, Ordering::SeqCst);
    let authority_fixture = request["messages"].as_array().is_some_and(|messages| {
        messages
            .iter()
            .any(|message| message["content"] == "authority-fixture")
    });
    let body = if authority_fixture {
        let chunk = json!({"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"authority-call","function":{"name":state.model_tool_name,"arguments":"{\"message\":\"hello\"}"}}]}}]});
        format!("data: {chunk}\n\ndata: [DONE]\n\n")
    } else if request_number == 0 {
        let tool_chunk = json!({
            "choices": [{
                "index": 0,
                "delta": {
                    "reasoning_content": "fixture reasoning for tool round trip",
                    "tool_calls": [{
                        "index": 0,
                        "id": "call_echo",
                        "function": {
                            "name": state.model_tool_name,
                            "arguments": "{\"message\":\"hello\"}",
                        },
                    }, {
                        "index": 1,
                        "id": "call_read_work_item",
                        "function": { "name": state.read_tool_name, "arguments": "{}" },
                    }, {
                        "index": 2,
                        "id": "call_read_unrelated",
                        "function": {
                            "name": state.read_tool_name,
                            "arguments": json!({ "work_item_id": state.other_work_item_id }).to_string(),
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
        let has_reasoning = request["messages"].as_array().is_some_and(|messages| {
            messages.iter().all(|message| {
                let original_round = message["tool_calls"]
                    .as_array()
                    .is_some_and(|calls| calls.iter().any(|call| call["id"] == "call_echo"));
                !original_round
                    || message["reasoning_content"] == "fixture reasoning for tool round trip"
            })
        });
        if !has_tool_result || !has_reasoning {
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

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
async fn verify_code_checkpoints(
    pool: &sqlx::PgPool,
    runtime: &sqlx::PgPool,
    original: Uuid,
    session: Uuid,
    organization: Uuid,
    workspace: Uuid,
    envelope: Arc<dyn EnvelopeCipher>,
) {
    use zeus_api::execution::code_workspace::{CodeScope, CodeStorage};
    let root = std::env::temp_dir().join(format!("zeus-runtime-code-{}", Uuid::now_v7()));
    let source = root.join("source");
    std::fs::create_dir_all(&source).unwrap();
    let git = |args: &[&str]| {
        let output = std::process::Command::new("/usr/bin/git")
            .current_dir(&source)
            .args([
                "-c",
                "core.hooksPath=/dev/null",
                "-c",
                "commit.gpgSign=false",
                "-c",
                "user.name=Test",
                "-c",
                "user.email=test@zeus.invalid",
            ])
            .args(args)
            .output()
            .unwrap();
        assert!(output.status.success());
        String::from_utf8(output.stdout).unwrap().trim().to_owned()
    };
    git(&["init"]);
    std::fs::write(source.join("README.md"), "checkpoint fixture").unwrap();
    git(&["add", "."]);
    git(&["commit", "-m", "fixture"]);
    let commit = git(&["rev-parse", "HEAD"]);
    let storage = Arc::new(CodeStorage::new(&root.join("managed")).await.unwrap());
    let repository = Uuid::now_v7();
    let id = Uuid::now_v7();
    let scope = CodeScope {
        organization_id: organization,
        workspace_id: workspace,
        run_id: id,
        fence: 1,
    };
    storage
        .import(scope, repository, source.to_str().unwrap())
        .await
        .unwrap();
    let version = Uuid::now_v7();
    sqlx::query("insert into workflow_versions (id, organization_id, workspace_id, workflow_id,
      version_number, agent_version_id, model_profile_id, input_schema, output_schema, code_repository)
      select $1, organization_id, workspace_id, workflow_id, version_number + 2,
      agent_version_id, model_profile_id, input_schema, output_schema, $3 from workflow_versions where id=$2")
      .bind(version).bind(original).bind(json!({"repository_id":repository,"commit":commit}))
      .execute(pool).await.unwrap();
    sqlx::query("insert into runs (id, organization_id, workspace_id, workflow_version_id, session_id, idempotency_key)
      values ($1,$2,$3,$4,$5,$6)").bind(id).bind(organization).bind(workspace).bind(version).bind(session)
      .bind(id.to_string()).execute(pool).await.unwrap();
    // Recovery of an already persisted model result exercises Git without another model side effect.
    sqlx::query("select zeus_private.append_run_event($1,'model.final','{\"output\":{\"content\":\"saved result\"}}')")
      .bind(id).execute(pool).await.unwrap();
    let claimed =
        sqlx::query_as::<_, ClaimedRun>("select * from zeus_private.claim_run('code-test',30)")
            .fetch_one(runtime)
            .await
            .unwrap();
    assert_eq!(claimed.run_id, id);
    let executor =
        DurableRunExecutor::new(runtime.clone(), "code-test".to_owned(), envelope.clone())
            .with_code_storage(storage.clone());
    assert!(matches!(
        executor.execute(&claimed, CancellationToken::new()).await,
        RunOutcome::Succeeded(_)
    ));
    assert!(
        !storage
            .directory(CodeScope {
                fence: claimed.fence_token,
                ..scope
            })
            .exists()
    );
    let count: i64 =
        sqlx::query_scalar("select count(*) from run_code_checkpoints where run_id=$1")
            .bind(id)
            .fetch_one(pool)
            .await
            .unwrap();
    assert_eq!(count, 1);
    let mut tenant = pool.begin().await.unwrap();
    sqlx::query("set local role zeus_http")
        .execute(&mut *tenant)
        .await
        .unwrap();
    for (tenant_workspace, expected) in [(workspace, 1_i64), (Uuid::now_v7(), 0_i64)] {
        sqlx::query("select set_config('zeus.organization_id',$1,true), set_config('zeus.workspace_id',$2,true)")
            .bind(organization.to_string()).bind(tenant_workspace.to_string())
            .execute(&mut *tenant).await.unwrap();
        let visible: i64 =
            sqlx::query_scalar("select count(*) from run_code_checkpoints where run_id=$1")
                .bind(id)
                .fetch_one(&mut *tenant)
                .await
                .unwrap();
        assert_eq!(
            visible, expected,
            "HTTP checkpoint reads respect tenant RLS"
        );
    }
    tenant.rollback().await.unwrap();
    for fence in [None, Some(claimed.fence_token - 1)] {
        assert!(
            sqlx::query("select zeus_private.save_code_checkpoint($1,'code-test',$2,$3,$4)")
                .bind(id)
                .bind(fence)
                .bind(Uuid::now_v7())
                .bind(&commit)
                .execute(runtime)
                .await
                .is_err()
        );
    }
    sqlx::query("update runs set lease_expires_at=now()-interval '1 second' where id=$1")
        .bind(id)
        .execute(pool)
        .await
        .unwrap();
    assert!(
        sqlx::query("select zeus_private.save_code_checkpoint($1,'code-test',$2,$3,$4)")
            .bind(id)
            .bind(claimed.fence_token)
            .bind(Uuid::now_v7())
            .bind(&commit)
            .execute(runtime)
            .await
            .is_err()
    );
    let resumed =
        sqlx::query_as::<_, ClaimedRun>("select * from zeus_private.claim_run('code-test',30)")
            .fetch_one(runtime)
            .await
            .unwrap();
    assert!(resumed.fence_token > claimed.fence_token);
    assert!(matches!(
        executor.execute(&resumed, CancellationToken::new()).await,
        RunOutcome::Succeeded(_)
    ));
    let restored: bool = sqlx::query_scalar(
        "select (payload->>'restored')::boolean from run_events where run_id=$1
      and event_type='code.prepared' order by sequence desc limit 1",
    )
    .bind(id)
    .fetch_one(pool)
    .await
    .unwrap();
    assert!(restored);
    assert!(
        sqlx::query("update run_code_checkpoints set checkpoint_commit=$2 where run_id=$1")
            .bind(id)
            .bind(&commit)
            .execute(pool)
            .await
            .is_err(),
        "checkpoints are immutable"
    );
    sqlx::query("select zeus_private.finish_run($1,'code-test',$2,'succeeded','{}',null,null)")
        .bind(id)
        .bind(resumed.fence_token)
        .execute(runtime)
        .await
        .unwrap();
    verify_sandbox_checkpoint(
        pool, runtime, original, session, scope, repository, &commit, storage, envelope,
    )
    .await;
    std::fs::remove_dir_all(root).unwrap();
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
async fn verify_sandbox_checkpoint(
    pool: &sqlx::PgPool,
    runtime: &sqlx::PgPool,
    original: Uuid,
    _session: Uuid,
    scope: zeus_api::execution::code_workspace::CodeScope,
    repository: Uuid,
    commit: &str,
    storage: Arc<zeus_api::execution::code_workspace::CodeStorage>,
    envelope: Arc<dyn EnvelopeCipher>,
) {
    use base64::{Engine, engine::general_purpose::STANDARD};
    use zeus_api::execution::sandbox::SandboxClient;
    let calls = Arc::new(AtomicUsize::new(0));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let observed = calls.clone();
    let server = tokio::spawn(async move {
        axum::serve(listener, Router::new()
            .route("/execute", post(move |Json(body): Json<serde_json::Value>| {
                let observed = observed.clone();
                async move {
                    observed.fetch_add(1, Ordering::SeqCst);
                    assert_eq!(body["script"], "printf sandbox > result.txt");
                    assert!(body["files"].as_array().unwrap().iter().all(|f| !f["path"].as_str().unwrap().starts_with(".git")));
                    let mut files = body["files"].as_array().unwrap().clone();
                    files.push(json!({"path":"result.txt","data":STANDARD.encode(b"sandbox"),"executable":false}));
                    Json(json!({"status":"completed","exit_code":0,"output":"fixture completed","files":files}))
                }
            }))
            .route("/jobs/{id}/renew", post(|| async { Json(json!({"active":true})) }))
            .route("/jobs/{id}/cancel", post(|| async { Json(json!({"active":false})) })))
            .await.unwrap();
    });
    let client = SandboxClient::new(
        &format!("http://{address}/"),
        SecretString::from("sandbox-test-authentication-fixture".to_owned()),
    )
    .unwrap();
    let capability = Uuid::now_v7();
    let version = Uuid::now_v7();
    let id = Uuid::now_v7();
    let tool = Uuid::now_v7();
    let organization = scope.organization_id;
    let workspace = scope.workspace_id;
    let session = Uuid::now_v7();
    sqlx::query("insert into sessions(id,organization_id,workspace_id,title) values($1,$2,$3,'Sandbox isolated session')")
      .bind(session).bind(organization).bind(workspace).execute(pool).await.unwrap();

    sqlx::query("insert into capability_definitions (id,organization_id,registry_key,display_name,description,input_schema,output_schema,idempotency_mode,risk_level,executor_key)
      values ($1,$2,'test.sandbox','Sandbox','Sandbox fixture','{}','{}','supported','low','builtin.sandbox_exec')")
      .bind(capability).bind(organization).execute(pool).await.unwrap();
    sqlx::query("insert into workspace_capabilities (organization_id,workspace_id,capability_id) values ($1,$2,$3)")
      .bind(organization).bind(workspace).bind(capability).execute(pool).await.unwrap();
    sqlx::query("insert into workflow_versions (id,organization_id,workspace_id,workflow_id,version_number,agent_version_id,model_profile_id,input_schema,output_schema,code_repository,execution_environment,capability_policy)
      select $1,organization_id,workspace_id,workflow_id,version_number+3,agent_version_id,model_profile_id,input_schema,output_schema,$3,$4,'{\"allowed\":[\"test.sandbox\"]}' from workflow_versions where id=$2")
      .bind(version).bind(original).bind(json!({"repository_id":repository,"commit":commit})).bind(format!("sha256:{}","a".repeat(64)))
      .execute(pool).await.unwrap();
    sqlx::query("insert into runs(id,organization_id,workspace_id,workflow_version_id,session_id,idempotency_key) values($1,$2,$3,$4,$5,$6)")
      .bind(id).bind(organization).bind(workspace).bind(version).bind(session).bind(id.to_string()).execute(pool).await.unwrap();
    let claimed =
        sqlx::query_as::<_, ClaimedRun>("select * from zeus_private.claim_run('sandbox-test',30)")
            .fetch_one(runtime)
            .await
            .unwrap();
    assert_eq!(claimed.run_id, id);
    sqlx::query("insert into tool_calls(id,organization_id,workspace_id,run_id,session_id,capability_id,call_key,fence_token,status,input)
      values($1,$2,$3,$4,$5,$6,'sandbox-call',$7,'pending_approval',$8)")
      .bind(tool).bind(organization).bind(workspace).bind(id).bind(session).bind(capability).bind(claimed.fence_token)
      .bind(json!({"script":"printf sandbox > result.txt"})).execute(pool).await.unwrap();
    sqlx::query("select zeus_private.append_session_event($1,'tool_call','system',null,$2,$3)")
      .bind(session).bind(json!({"call_id":"sandbox-call","capability":format!("cap_{}",capability.simple()),"arguments":{"script":"printf sandbox > result.txt"}})).bind(id)
      .execute(pool).await.unwrap();
    sqlx::query("insert into approvals(organization_id,workspace_id,run_id,tool_call_id) values($1,$2,$3,$4)")
      .bind(organization).bind(workspace).bind(id).bind(tool).execute(pool).await.unwrap();
    let executor = DurableRunExecutor::new(runtime.clone(), "sandbox-test".to_owned(), envelope)
        .with_code_storage(storage.clone())
        .with_sandbox(client);
    assert!(matches!(
        executor.execute(&claimed, CancellationToken::new()).await,
        RunOutcome::WaitingApproval
    ));
    assert_eq!(
        calls.load(Ordering::SeqCst),
        0,
        "pending approval must not reach the adapter"
    );
    sqlx::query(
        "select zeus_private.finish_run($1,'sandbox-test',$2,'waiting_approval',null,null,null)",
    )
    .bind(id)
    .bind(claimed.fence_token)
    .execute(runtime)
    .await
    .unwrap();
    sqlx::query("update approvals set status='approved' where tool_call_id=$1")
        .bind(tool)
        .execute(pool)
        .await
        .unwrap();
    sqlx::query("update tool_calls set status='ready' where id=$1")
        .bind(tool)
        .execute(pool)
        .await
        .unwrap();
    sqlx::query("update runs set status='queued',available_at=now() where id=$1")
        .bind(id)
        .execute(pool)
        .await
        .unwrap();
    let resumed =
        sqlx::query_as::<_, ClaimedRun>("select * from zeus_private.claim_run('sandbox-test',30)")
            .fetch_one(runtime)
            .await
            .unwrap();
    // Exercise the dedicated authorization decision with the real Runtime role.
    sqlx::query("update tool_calls set status='running',fence_token=$2 where id=$1")
        .bind(tool)
        .bind(resumed.fence_token)
        .execute(pool)
        .await
        .unwrap();
    let authorized = |fence| async move {
        sqlx::query_scalar::<_, bool>(
            "select zeus_private.sandbox_execution_authorized($1,$2,$3,$4,'sandbox-test',$5)",
        )
        .bind(id)
        .bind(organization)
        .bind(workspace)
        .bind(fence)
        .bind(tool)
        .fetch_one(runtime)
        .await
        .unwrap()
    };
    assert!(authorized(resumed.fence_token).await);
    assert!(!authorized(resumed.fence_token - 1).await);
    sqlx::query("update workspace_capabilities set enabled=false where capability_id=$1")
        .bind(capability)
        .execute(pool)
        .await
        .unwrap();
    assert!(
        !authorized(resumed.fence_token).await,
        "revoked capability must stop execution"
    );
    sqlx::query("update workspace_capabilities set enabled=true where capability_id=$1")
        .bind(capability)
        .execute(pool)
        .await
        .unwrap();
    sqlx::query("update organizations set status='suspended' where id=$1")
        .bind(organization)
        .execute(pool)
        .await
        .unwrap();
    assert!(
        !authorized(resumed.fence_token).await,
        "suspended organization must stop execution"
    );
    sqlx::query("update organizations set status='active' where id=$1")
        .bind(organization)
        .execute(pool)
        .await
        .unwrap();
    sqlx::query("update tool_calls set status='ready' where id=$1")
        .bind(tool)
        .execute(pool)
        .await
        .unwrap();
    let outcome = executor.execute(&resumed, CancellationToken::new()).await;
    assert!(matches!(outcome, RunOutcome::Succeeded(_)), "{outcome:?}");
    let error: Option<String> = sqlx::query_scalar("select error_code from tool_calls where id=$1")
        .bind(tool)
        .fetch_one(pool)
        .await
        .unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 1, "tool error: {error:?}");
    let status: String = sqlx::query_scalar("select status from tool_calls where id=$1")
        .bind(tool)
        .fetch_one(pool)
        .await
        .unwrap();
    assert_eq!(status, "succeeded");
    let saved: String=sqlx::query_scalar("select checkpoint_commit from run_code_checkpoints where run_id=$1 order by created_at desc,id desc limit 1").bind(id).fetch_one(pool).await.unwrap();
    let restored = zeus_api::execution::code_workspace::CodeScope {
        run_id: id,
        fence: resumed.fence_token + 1,
        ..scope
    };
    let binding = zeus_api::execution::code_workspace::RepositoryBinding {
        repository_id: repository,
        commit: commit.to_owned(),
    };
    storage
        .prepare(restored, &binding, Some(&saved))
        .await
        .unwrap();
    assert_eq!(
        std::fs::read(storage.directory(restored).join("result.txt")).unwrap(),
        b"sandbox"
    );
    storage.release(restored, &binding).await.unwrap();
    sqlx::query("select zeus_private.finish_run($1,'sandbox-test',$2,'succeeded','{}',null,null)")
        .bind(id)
        .bind(resumed.fence_token)
        .execute(runtime)
        .await
        .unwrap();
    server.abort();
}

#[allow(clippy::too_many_lines)] // Verify the durable write and its authorization gates with real roles.
async fn verify_studio_creation(
    pool: &sqlx::PgPool,
    runtime: &sqlx::PgPool,
    source: Uuid,
    session: Uuid,
    actor: Uuid,
) {
    let capability = Uuid::now_v7();
    sqlx::query("insert into capability_definitions (id, organization_id, registry_key, display_name, description, input_schema, output_schema, idempotency_mode, risk_level, executor_key) select $1, organization_id, 'zeus.studio-resource-create', 'Chat', 'Create', '{}', '{}', 'supported', 'low', 'builtin.studio_resource_create' from workflow_versions where id = $2")
        .bind(capability).bind(source).execute(pool).await.unwrap();
    sqlx::query("insert into workspace_capabilities (organization_id, workspace_id, capability_id) select organization_id, workspace_id, $1 from workflow_versions where id = $2")
        .bind(capability).bind(source).execute(pool).await.unwrap();
    let version = Uuid::now_v7();
    sqlx::query("insert into workflow_versions (id, organization_id, workspace_id, workflow_id, version_number, agent_version_id, model_profile_id, input_schema, output_schema, capability_policy) select $1, organization_id, workspace_id, workflow_id, 900, agent_version_id, model_profile_id, '{}', '{}', '{\"allowed\":[\"zeus.studio-resource-create\"]}' from workflow_versions where id = $2")
        .bind(version).bind(source).execute(pool).await.unwrap();
    let run = Uuid::now_v7();
    sqlx::query("insert into runs (id, organization_id, workspace_id, workflow_version_id, session_id, idempotency_key, created_by, status, fence_token, lease_owner, lease_expires_at) select $1, organization_id, workspace_id, $2, $3, $1::text, $4, 'running', 1, 'studio-test', now() + interval '10 minutes' from workflow_versions where id = $2")
        .bind(run).bind(version).bind(session).bind(actor).execute(pool).await.unwrap();
    for kind in ["work_item", "workflow"] {
        let call = Uuid::now_v7();
        sqlx::query("insert into tool_calls (id, organization_id, workspace_id, run_id, session_id, capability_id, call_key, fence_token, status, input) select $1, organization_id, workspace_id, id, session_id, $3, $1::text, 1, 'running', $4 from runs where id = $2")
            .bind(call).bind(run).bind(capability).bind(json!({"kind":kind,"title":format!("Chat {call}"),"description":"A concrete task"})).execute(pool).await.unwrap();
        let invoke = || {
            sqlx::query_scalar::<_, serde_json::Value>(
                "select zeus_private.create_studio_resource($1, 'studio-test', 1, $2)",
            )
            .bind(run)
            .bind(call)
            .fetch_one(runtime)
        };
        sqlx::query("update runs set input = '{}' where id = $1")
            .bind(run)
            .execute(pool)
            .await
            .unwrap();
        let proposed = invoke().await.expect("default is preview");
        assert_eq!(proposed["status"], "proposed");
        assert_eq!(proposed["description"], "A concrete task");
        let writes: i64 = sqlx::query_scalar("select (select count(*) from work_items where id=$1) + (select count(*) from workflows where id=$1)").bind(call).fetch_one(pool).await.unwrap();
        assert_eq!(writes, 0, "preview must not create domain resources");
        sqlx::query(
            "update runs set input = '{\"studio_resource_mode\":\"create\"}' where id = $1",
        )
        .bind(run)
        .execute(pool)
        .await
        .unwrap();
        let created = invoke()
            .await
            .expect("runtime can create a scoped resource");
        assert_eq!(created["id"], call.to_string());
        assert_eq!(
            created,
            invoke().await.expect("retry returns the same resource")
        );
        let audits: i64 = sqlx::query_scalar("select count(*) from audit_events where target_id = $1 and action = 'studio.resource_created'").bind(call).fetch_one(pool).await.unwrap();
        assert_eq!(audits, 1);
        assert!(
            sqlx::query_scalar::<_, serde_json::Value>(
                "select zeus_private.create_studio_resource($1, 'old-node', 1, $2)"
            )
            .bind(run)
            .bind(call)
            .fetch_one(runtime)
            .await
            .is_err()
        );
        sqlx::query("update workspace_capabilities set enabled = false where capability_id = $1")
            .bind(capability)
            .execute(pool)
            .await
            .unwrap();
        assert!(invoke().await.is_err(), "disabled tool is not replayed");
        sqlx::query("update workspace_capabilities set enabled = true, approval_required = true where capability_id = $1").bind(capability).execute(pool).await.unwrap();
        assert!(invoke().await.is_err(), "approval is still required");
        sqlx::query(
            "update workspace_capabilities set approval_required = false where capability_id = $1",
        )
        .bind(capability)
        .execute(pool)
        .await
        .unwrap();
        sqlx::query("update runs set created_by = null where id = $1")
            .bind(run)
            .execute(pool)
            .await
            .unwrap();
        assert!(
            invoke().await.is_err(),
            "a service actor cannot borrow owner rights"
        );
        sqlx::query("update runs set created_by = $2 where id = $1")
            .bind(run)
            .bind(actor)
            .execute(pool)
            .await
            .unwrap();
        if kind == "workflow" {
            let unpublished: bool =
                sqlx::query_scalar("select active_version_id is null from workflows where id = $1")
                    .bind(call)
                    .fetch_one(pool)
                    .await
                    .unwrap();
            assert!(unpublished);
        } else {
            let open: bool = sqlx::query_scalar("select status = 'open' and source_kind = 'studio_discussion' from work_items where id = $1").bind(call).fetch_one(pool).await.unwrap();
            assert!(open);
        }
    }
    let extra = Uuid::now_v7();
    sqlx::query("insert into tool_calls (id, organization_id, workspace_id, run_id, session_id, capability_id, call_key, fence_token, status, input) select $1, organization_id, workspace_id, id, session_id, $3, $1::text, 1, 'running', $4 from runs where id = $2")
        .bind(extra).bind(run).bind(capability).bind(json!({"kind":"work_item","title":"invalid","description":"scope injection","workspace_id":Uuid::now_v7()})).execute(pool).await.unwrap();
    assert!(
        sqlx::query_scalar::<_, serde_json::Value>(
            "select zeus_private.create_studio_resource($1, 'studio-test', 1, $2)"
        )
        .bind(run)
        .bind(extra)
        .fetch_one(runtime)
        .await
        .is_err()
    );
    sqlx::query("update runs set status = 'succeeded', finished_at = now(), lease_owner = null, lease_expires_at = null where id = $1").bind(run).execute(pool).await.unwrap();
}

#[allow(clippy::too_many_lines)]
async fn verify_resource_approval_request(
    pool: &sqlx::PgPool,
    runtime: &sqlx::PgPool,
    version: Uuid,
    capability: Uuid,
    actor: Uuid,
    envelope: Arc<dyn EnvelopeCipher>,
) {
    let session = Uuid::now_v7();
    sqlx::query("insert into sessions(id,organization_id,workspace_id,title) select $1,organization_id,workspace_id,'Authority fixture' from workflow_versions where id=$2")
        .bind(session).bind(version).execute(pool).await.unwrap();
    let run = Uuid::now_v7();
    sqlx::query("insert into runs(id,organization_id,workspace_id,workflow_version_id,session_id,created_by,idempotency_key,status,fence_token,lease_owner,lease_expires_at)
        select $1,organization_id,workspace_id,id,$3,$4,$1::text,'running',1,'authority-test',now()+interval '10 minutes' from workflow_versions where id=$2")
        .bind(run).bind(version).bind(session).bind(actor).execute(pool).await.unwrap();
    sqlx::query("select * from zeus_private.append_session_event($1,'user_message','user',$2,'{\"content\":\"authority-fixture\"}',$3)")
        .bind(session).bind(actor).bind(run).execute(pool).await.unwrap();
    sqlx::query("update workspace_capabilities set policy='{\"resource_authorization_required\":true}' where capability_id=$1")
        .bind(capability).execute(pool).await.unwrap();
    let claimed: ClaimedRun = sqlx::query_as("select id as run_id,organization_id,workspace_id,session_id,workflow_version_id,fence_token,1::integer as attempt_number from runs where id=$1")
        .bind(run).fetch_one(pool).await.unwrap();
    let executor = DurableRunExecutor::new(runtime.clone(), "authority-test".into(), envelope);
    let outcome = executor.execute(&claimed, CancellationToken::new()).await;
    assert!(
        matches!(outcome, RunOutcome::WaitingApproval),
        "{outcome:?}"
    );
    let approval: (String,Option<Uuid>,serde_json::Value,i64,i64) = sqlx::query_as("select kind,requested_by,input_snapshot,capability_revision,binding_revision from approvals where run_id=$1")
        .bind(run).fetch_one(pool).await.unwrap();
    assert_eq!(approval.0, "resource_access");
    assert_eq!(approval.1, Some(actor));
    assert_eq!(approval.2, json!({"message":"hello"}));
    assert!(approval.3 > 0 && approval.4 > 0);
    sqlx::query(
        "select zeus_private.finish_run($1,'authority-test',1,'waiting_approval',null,null,null)",
    )
    .bind(run)
    .execute(runtime)
    .await
    .unwrap();
    let suspended: (String, bool, bool) = sqlx::query_as(
        "select status,lease_owner is null,lease_expires_at is null from runs where id=$1",
    )
    .bind(run)
    .fetch_one(pool)
    .await
    .unwrap();
    assert_eq!(suspended, ("waiting_approval".into(), true, true));
    sqlx::query("update workspace_capabilities set policy='{}' where capability_id=$1")
        .bind(capability)
        .execute(pool)
        .await
        .unwrap();
}
