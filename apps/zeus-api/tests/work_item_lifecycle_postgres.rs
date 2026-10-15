//! Isolated, synthetic chat-to-goal acceptance. No real model or external side effects.
use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, HeaderValue},
    response::Response,
};
use http_body_util::BodyExt;
use secrecy::SecretString;
use serde_json::Value;
use sqlx::PgPool;
use std::{collections::BTreeSet, sync::Arc, time::Duration};
use uuid::Uuid;
use zeus_api::{
    AppState, ExecutionRuntimeConfig, ExternalClients, HTTP_DATABASE_ROLE, IdentityRuntimeConfig,
    PlatformServices,
    auth::{AuthContext, PrincipalKind},
    collaboration::{
        im_agents::{self, ImInvokeAgent},
        work_item_archive::{self, ArchiveWorkItemRequest},
        work_items::{self, CreateWorkItemReviewRequest, UpdateWorkItemRequest},
    },
    connect_pool, connect_pool_as_role,
    crypto::LocalEnvelopeCipher,
    database::{TenantScope, begin_tenant},
    error::ApiError,
    execution_api::{self, RetryRunRequest},
    migrate,
    supervisor::SupervisorMetrics,
};
use zeus_core::{OrganizationRole, WorkspaceRole};
use zeus_identity::{PasswordExecutor, PasswordPolicy};

fn state(database: PgPool) -> AppState {
    // Ephemeral fixture encryption key; never a deployment credential.
    let key = SecretString::from("11".repeat(32));
    AppState {
        platform: Arc::new(PlatformServices {
            database,
            envelope: Arc::new(LocalEnvelopeCipher::from_encoded("fixture".into(), &key).unwrap()),
            metrics: Arc::new(SupervisorMetrics::default()),
            version: "test",
        }),
        identity: Arc::new(IdentityRuntimeConfig {
            public_url: "http://127.0.0.1:3199".parse().unwrap(),
            session_idle_ttl: Duration::from_hours(1),
            session_absolute_ttl: Duration::from_hours(2),
            oidc_state_ttl: Duration::from_mins(10),
            cookie_secure: false,
            allow_private_oidc_issuers: false,
            bootstrap_token: None,
            identity_hash_key: key,
            trust_proxy_headers: false,
            password_executor: PasswordExecutor::new(1, 1, PasswordPolicy::default()).unwrap(),
        }),
        external: Arc::new(ExternalClients {
            http: reqwest::Client::new(),
        }),
        execution: Arc::new(ExecutionRuntimeConfig {
            allow_private_model_endpoints: true,
        }),
    }
}
fn actor(org: Uuid, workspace: Uuid, user: Uuid) -> AuthContext {
    AuthContext {
        principal_kind: PrincipalKind::User,
        principal_id: user,
        user_id: Some(user),
        session_id: None,
        tenant_access_grant_id: None,
        tenant_access_reason: None,
        tenant_access_expires_at: None,
        organization_id: org,
        workspace_id: Some(workspace),
        organization_role: Some(OrganizationRole::Owner),
        workspace_role: Some(WorkspaceRole::Owner),
        scopes: BTreeSet::new(),
        email: None,
        display_name: "Fixture Owner".into(),
        authenticated_at: None,
        mfa_satisfied_at: None,
        platform_roles: BTreeSet::new(),
    }
}
fn headers(key: &str, revision: i64) -> HeaderMap {
    let mut result = HeaderMap::new();
    result.insert("idempotency-key", HeaderValue::from_str(key).unwrap());
    result.insert(
        "if-match",
        HeaderValue::from_str(&format!("\"revision-{revision}\"")).unwrap(),
    );
    result
}
async fn body(response: Response) -> Value {
    assert!(response.status().is_success());
    serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap()
}
async fn revision(pool: &PgPool, item: Uuid) -> i64 {
    sqlx::query_scalar("select revision from work_items where id=$1")
        .bind(item)
        .fetch_one(pool)
        .await
        .unwrap()
}
async fn accept(
    state: &AppState,
    auth: &AuthContext,
    pool: &PgPool,
    item: Uuid,
    run: Uuid,
    decision: &str,
) -> Uuid {
    work_items::create_work_item_review(
        State(state.clone()),
        auth.clone(),
        Path((auth.workspace_id.unwrap(), item)),
        headers("review", revision(pool, item).await),
        Json(CreateWorkItemReviewRequest {
            run_id: run,
            decision: decision.into(),
            reason: "Synthetic test output and mock log evidence checked".into(),
        }),
    )
    .await
    .unwrap()
    .1
    .0
    .id
}
async fn archive(
    state: &AppState,
    auth: &AuthContext,
    item: Uuid,
    review: Uuid,
    revision: i64,
) -> Result<Response, ApiError> {
    work_item_archive::archive(
        State(state.clone()),
        auth.clone(),
        Path((auth.workspace_id.unwrap(), item)),
        headers(&format!("archive-{review}-{revision}"), revision),
        Json(ArchiveWorkItemRequest {
            review_id: review,
            resolution_summary:
                "Mock adapter and synthetic logs confirm the test goal was resolved".into(),
        }),
    )
    .await
}
async fn simulate_result(pool: &PgPool, run: Uuid, status: &str) {
    // This is an external-adapter simulation, not proof of a real merge or deployment.
    sqlx::query("update runs set status=$2,output=case when $2='succeeded' then '{\"content\":\"Synthetic test result\"}'::jsonb else null end,finished_at=clock_timestamp() where id=$1")
        .bind(run).bind(status).execute(pool).await.unwrap();
}

#[tokio::test]
#[ignore = "requires isolated ZEUS_TEST_DATABASE_URL"]
#[allow(clippy::too_many_lines)]
async fn chat_goal_survives_attempts_and_requires_current_owner_evidence_to_archive() {
    let pool = connect_pool(&std::env::var("ZEUS_TEST_DATABASE_URL").unwrap(), 5)
        .await
        .unwrap();
    migrate(&pool).await.unwrap();
    let http = connect_pool_as_role(
        &std::env::var("ZEUS_TEST_DATABASE_URL").unwrap(),
        5,
        HTTP_DATABASE_ROLE,
    )
    .await
    .unwrap();
    let state = state(http.clone());
    let org = Uuid::now_v7();
    let workspace = Uuid::now_v7();
    let user = Uuid::now_v7();
    let peer = Uuid::now_v7();
    let connection = Uuid::now_v7();
    let model = Uuid::now_v7();
    let agent = Uuid::now_v7();
    let av = Uuid::now_v7();
    let workflow = Uuid::now_v7();
    let version = Uuid::now_v7();
    sqlx::raw_sql(&format!(r"
      insert into organizations(id,slug,name,status) values('{org}','{org}','Synthetic organization','provisioning');
      insert into users(id,email,display_name,status,email_verified_at) values('{user}','{user}@example.invalid','Owner','active',now()),('{peer}','{peer}@example.invalid','Operator','active',now());
      insert into organization_memberships(organization_id,user_id,role,status) values('{org}','{user}','owner','active'),('{org}','{peer}','owner','active');
      update organizations set status='active' where id='{org}';
      insert into workspaces(id,organization_id,slug,name) values('{workspace}','{org}','{workspace}','Synthetic workspace');
      insert into workspace_memberships(organization_id,workspace_id,user_id,role,status) values('{org}','{workspace}','{user}','owner','active'),('{org}','{workspace}','{peer}','operator','active');
      insert into connections(id,organization_id,name,provider_kind) values('{connection}','{org}','Mock provider','openai_compatible');
      insert into model_profiles(id,organization_id,connection_id,name,base_url,model) values('{model}','{org}','{connection}','Mock model','https://example.invalid/v1','fixture');
      insert into agents(id,organization_id,workspace_id,name) values('{agent}','{org}','{workspace}','Repair');
      insert into agent_versions(id,organization_id,workspace_id,agent_id,version_number,instructions) values('{av}','{org}','{workspace}','{agent}',1,'Use approved tools and report verification');
      insert into workflows(id,organization_id,workspace_id,name) values('{workflow}','{org}','{workspace}','Repair');
      insert into workflow_versions(id,organization_id,workspace_id,workflow_id,version_number,agent_version_id,model_profile_id,input_schema,output_schema) values('{version}','{org}','{workspace}','{workflow}',1,'{av}','{model}','{{}}','{{}}');
      update workflows set active_version_id='{version}' where id='{workflow}';
    ")).execute(&pool).await.unwrap();
    let auth = actor(org, workspace, user);
    let mut tx = begin_tenant(&http, TenantScope::organization(Some(user), org))
        .await
        .unwrap();
    let conv: Uuid =
        sqlx::query_scalar("select zeus_private.im_create($1,'group','Synthetic issue',$2,$3)")
            .bind(org)
            .bind(vec![peer])
            .bind(Uuid::now_v7())
            .fetch_one(&mut *tx)
            .await
            .unwrap();
    tx.commit().await.unwrap();
    let member = im_agents::add(
        State(state.clone()),
        auth.clone(),
        Path((workspace, conv)),
        Json(im_agents::ImAddAgent {
            workflow_version_id: version,
        }),
    )
    .await
    .unwrap()
    .0
    .id;
    let mut tx = begin_tenant(&http, TenantScope::organization(Some(user), org))
        .await
        .unwrap();
    let source: Uuid = sqlx::query_scalar(
        "select zeus_private.im_send($1,$2,'Investigate synthetic log failure',null,'{}'::uuid[])",
    )
    .bind(conv)
    .bind(Uuid::now_v7())
    .fetch_one(&mut *tx)
    .await
    .unwrap();
    tx.commit().await.unwrap();
    let invocation = || {
        im_agents::invoke(
            State(state.clone()),
            auth.clone(),
            Path((workspace, conv)),
            headers(&format!("im:{member}:{source}"), 1),
            Json(ImInvokeAgent {
                agent_member_id: member,
                source_message_id: source,
                create_work_item: true,
            }),
        )
    };
    let (first, duplicate) = tokio::join!(invocation(), invocation());
    let first = first.unwrap().0;
    let duplicate = duplicate.unwrap().0;
    assert_eq!(first.id, duplicate.id);
    assert_eq!(first.work_item_id, duplicate.work_item_id);
    let item = first.work_item_id.unwrap();
    let linkage: (Uuid, Uuid, String, String) = sqlx::query_as("select r.work_item_id,s.work_item_id,w.description,w.source_kind from runs r join sessions s on s.id=r.session_id join work_items w on w.id=r.work_item_id where r.id=$1")
        .bind(first.id).fetch_one(&pool).await.unwrap();
    assert_eq!(
        linkage,
        (
            item,
            item,
            "Investigate synthetic log failure".into(),
            "im_agent".into()
        )
    );
    assert!(matches!(
        im_agents::invoke(
            State(state.clone()),
            auth.clone(),
            Path((workspace, conv)),
            headers(&format!("im:{member}:{source}"), 1),
            Json(ImInvokeAgent {
                agent_member_id: member,
                source_message_id: source,
                create_work_item: false
            })
        )
        .await,
        Err(ApiError::IdempotencyConflict)
    ));
    assert!(matches!(
        work_items::update_work_item(
            State(state.clone()),
            auth.clone(),
            Path((workspace, item)),
            headers("update", 1),
            Json(UpdateWorkItemRequest {
                status: Some("completed".into()),
                ..Default::default()
            })
        )
        .await,
        Err(ApiError::Conflict(_))
    ));
    assert!(
        archive(&state, &auth, item, Uuid::now_v7(), 1)
            .await
            .is_err(),
        "queued work cannot be archived"
    );
    simulate_result(&pool, first.id, "failed").await;
    assert!(
        archive(&state, &auth, item, Uuid::now_v7(), 1)
            .await
            .is_err(),
        "failure is not resolution"
    );
    let retry = body(
        execution_api::retry_run(
            State(state.clone()),
            auth.clone(),
            Path((workspace, first.id)),
            headers("retry-synthetic-issue", 1),
            Json(RetryRunRequest {}),
        )
        .await
        .unwrap(),
    )
    .await;
    let second = Uuid::parse_str(retry["id"].as_str().unwrap()).unwrap();
    assert_eq!(retry["work_item_id"], item.to_string());
    simulate_result(&pool, second, "succeeded").await;
    let changes = accept(&state, &auth, &pool, item, second, "needs_changes").await;
    assert!(
        archive(&state, &auth, item, changes, revision(&pool, item).await)
            .await
            .is_err()
    );
    let current = revision(&pool, item).await;
    let new_attempt = body(
        execution_api::reprocess_work_item_review(
            State(state.clone()),
            auth.clone(),
            Path((workspace, item, changes)),
            headers("reprocess-synthetic-issue", current),
        )
        .await
        .unwrap(),
    )
    .await;
    let third = Uuid::parse_str(new_attempt["run"]["id"].as_str().unwrap()).unwrap();
    assert_eq!(new_attempt["run"]["work_item_id"], item.to_string());
    assert_eq!(
        new_attempt["run"]["input"]["reprocessing"]["review_id"],
        changes.to_string()
    );
    let old_acceptance = accept(&state, &auth, &pool, item, second, "accepted").await;
    assert!(
        archive(
            &state,
            &auth,
            item,
            old_acceptance,
            revision(&pool, item).await
        )
        .await
        .is_err(),
        "a prior success cannot hide a new unfinished attempt"
    );
    simulate_result(&pool, third, "failed").await;
    assert!(
        archive(
            &state,
            &auth,
            item,
            old_acceptance,
            revision(&pool, item).await
        )
        .await
        .is_err(),
        "a prior success cannot hide a new failed attempt"
    );
    let fourth = body(
        execution_api::retry_run(
            State(state.clone()),
            auth.clone(),
            Path((workspace, third)),
            headers("retry-reprocessed-issue", 1),
            Json(RetryRunRequest {}),
        )
        .await
        .unwrap(),
    )
    .await;
    let final_run = Uuid::parse_str(fourth["id"].as_str().unwrap()).unwrap();
    simulate_result(&pool, final_run, "succeeded").await;
    let accepted = accept(&state, &auth, &pool, item, final_run, "accepted").await;
    let before_edit = revision(&pool, item).await;
    let _ = work_items::update_work_item(
        State(state.clone()),
        auth.clone(),
        Path((workspace, item)),
        headers("edit", before_edit),
        Json(UpdateWorkItemRequest {
            description: Some("Changed goal must be reviewed again".into()),
            ..Default::default()
        }),
    )
    .await
    .unwrap();
    assert!(matches!(
        archive(&state, &auth, item, accepted, before_edit).await,
        Err(ApiError::PreconditionFailed)
    ));
    assert!(
        archive(&state, &auth, item, accepted, revision(&pool, item).await)
            .await
            .is_err(),
        "acceptance cannot authorize changed content"
    );
    let accepted = accept(&state, &auth, &pool, item, final_run, "accepted").await;
    let current = revision(&pool, item).await;
    let mut operator = actor(org, workspace, peer);
    operator.workspace_role = Some(WorkspaceRole::Operator);
    assert!(matches!(
        archive(&state, &operator, item, accepted, current).await,
        Err(ApiError::Forbidden)
    ));
    let mut support = auth.clone();
    support.tenant_access_grant_id = Some(Uuid::now_v7());
    assert!(matches!(
        archive(&state, &support, item, accepted, current).await,
        Err(ApiError::Forbidden)
    ));
    let result = body(
        archive(&state, &auth, item, accepted, current)
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(result["run_id"], final_run.to_string());
    // A response lost after commit can be safely retried even after process/client restart.
    assert_eq!(
        body(
            archive(&state, &auth, item, accepted, current)
                .await
                .unwrap()
        )
        .await,
        result
    );
    let archived: (String, bool, i64) = sqlx::query_as(
        "select status,archived_at is not null,revision from work_items where id=$1",
    )
    .bind(item)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(archived, ("completed".into(), true, current + 1));
    assert!(
        sqlx::query(
            "update work_item_archives set resolution_summary='tamper' where work_item_id=$1"
        )
        .bind(item)
        .execute(&pool)
        .await
        .is_err()
    );
    assert!(
        sqlx::query("update work_items set description='tamper' where id=$1")
            .bind(item)
            .execute(&pool)
            .await
            .is_err()
    );
    assert!(sqlx::query("insert into runs(organization_id,workspace_id,workflow_version_id,work_item_id,session_id,idempotency_key) select organization_id,workspace_id,workflow_version_id,work_item_id,session_id,'post-archive' from runs where id=$1").bind(final_run).execute(&pool).await.is_err());
    let mut wrong_scope = auth.tenant_scope(Some(workspace));
    wrong_scope.workspace_id = Some(Uuid::now_v7());
    let mut tx = begin_tenant(&http, wrong_scope).await.unwrap();
    let hidden: i64 =
        sqlx::query_scalar("select count(*) from work_item_archives where work_item_id=$1")
            .bind(item)
            .fetch_one(&mut *tx)
            .await
            .unwrap();
    assert_eq!(hidden, 0);
    let snapshot_hidden: i64 =
        sqlx::query_scalar("select count(*) from run_model_configuration_bindings where run_id=$1")
            .bind(final_run)
            .fetch_one(&mut *tx)
            .await
            .unwrap();
    assert_eq!(snapshot_hidden, 0);
    tx.rollback().await.unwrap();
    let binding: (Uuid, i64, i64) = sqlx::query_as("select model_profile_id,model_profile_revision,octet_length(configuration_sha256)::bigint from run_model_configuration_bindings where run_id=$1").bind(first.id).fetch_one(&pool).await.unwrap();
    assert_eq!(binding, (model, 1, 32));
    assert!(
        sqlx::query(
            "update run_model_configuration_bindings set model_profile_revision=100 where run_id=$1"
        )
        .bind(first.id)
        .execute(&pool)
        .await
        .is_err()
    );
    let audits: i64 = sqlx::query_scalar(
        "select count(*) from audit_events where action='work_item.archived' and target_id=$1",
    )
    .bind(Uuid::parse_str(result["id"].as_str().unwrap()).unwrap())
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(audits, 1);
}
