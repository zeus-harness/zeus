use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    process::Command,
    sync::atomic::{AtomicU64, Ordering},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use protocol::{
    Approval, ApprovalScope, ApprovalStatus, AttachRunRequest, CreateSessionRequest, EventType,
    EvidenceSummary, FlushSessionRequest, IncidentStatus, IncidentSummary, Metric, MetricTone,
    ResumeSessionRequest, ReviewDecision, ReviewResponse, RunEvent, RunEventData, RunStatus,
    RunSummary, SandboxProfile, SessionEventData, SessionStatus, SessionTurnStatus, Severity,
    StartTurnRequest, ToolCall, ToolCallStatus, ToolEffect, ToolExecutorStatus, ToolOutcome,
    ToolPolicySummary,
};
use rusqlite::params;
use serde_json::json;

use crate::{
    ClaimOutcome, CommitOutcome, DispatchCompleteCommit, DispatchJobSpec, DispatchRecoveryCommit,
    DispatchStartCommit, DispatchStatus, ReviewCommit, RunSnapshot, RuntimeIdentity, SqliteStore,
    StorageError,
};

static NEXT_DATABASE: AtomicU64 = AtomicU64::new(0);
const RUN_ID: &str = "ZR-1842";
const LOCK_HELPER_DATABASE: &str = "ZEUS_STORAGE_LOCK_HELPER_DATABASE";
const LOCK_HELPER_READY: &str = "ZEUS_STORAGE_LOCK_HELPER_READY";
const LOCK_HELPER_RELEASE: &str = "ZEUS_STORAGE_LOCK_HELPER_RELEASE";

struct TestDatabase {
    path: PathBuf,
}

impl TestDatabase {
    fn new() -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock must be after Unix epoch")
            .as_nanos();
        let serial = NEXT_DATABASE.fetch_add(1, Ordering::Relaxed);
        Self {
            path: std::env::temp_dir().join(format!(
                "zeus-storage-{}-{nonce}-{serial}.sqlite3",
                std::process::id()
            )),
        }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TestDatabase {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
        let _ = fs::remove_file(self.path.with_extension("sqlite3-wal"));
        let _ = fs::remove_file(self.path.with_extension("sqlite3-shm"));
        let _ = fs::remove_file(format!("{}.zeus.lock", self.path.display()));
    }
}

#[tokio::test]
async fn persistent_store_has_one_owner_until_the_last_clone_drops() {
    let database = TestDatabase::new();
    let first = SqliteStore::open(database.path()).await.unwrap();
    let retained_clone = first.clone();

    let error = match SqliteStore::open(database.path()).await {
        Ok(_) => panic!("a second persistent owner must be rejected"),
        Err(error) => error,
    };
    assert!(matches!(error, StorageError::DatabaseLocked(_)));

    drop(first);
    let error = match SqliteStore::open(database.path()).await {
        Ok(_) => panic!("a retained clone must keep the database lease"),
        Err(error) => error,
    };
    assert!(matches!(error, StorageError::DatabaseLocked(_)));

    drop(retained_clone);
    SqliteStore::open(database.path()).await.unwrap();
}

#[test]
fn persistent_store_lock_is_exclusive_across_processes() {
    let database = TestDatabase::new();
    let ready = database.path.with_extension("lock-ready");
    let release = database.path.with_extension("lock-release");
    let mut child = Command::new(std::env::current_exe().unwrap())
        .arg("--exact")
        .arg("tests::persistent_store_lock_holder")
        .arg("--nocapture")
        .env(LOCK_HELPER_DATABASE, database.path())
        .env(LOCK_HELPER_READY, &ready)
        .env(LOCK_HELPER_RELEASE, &release)
        .spawn()
        .unwrap();

    let deadline = Instant::now() + Duration::from_secs(10);
    while !ready.exists() {
        if let Some(status) = child.try_wait().unwrap() {
            panic!("lock-holder child exited before acquiring the lease: {status}");
        }
        assert!(
            Instant::now() < deadline,
            "lock-holder child did not acquire the lease in time"
        );
        thread::sleep(Duration::from_millis(10));
    }

    let runtime = tokio::runtime::Runtime::new().unwrap();
    let error = match runtime.block_on(SqliteStore::open(database.path())) {
        Ok(_) => panic!("another process already owns the persistent database"),
        Err(error) => error,
    };
    assert!(matches!(error, StorageError::DatabaseLocked(_)));

    fs::write(&release, b"release").unwrap();
    assert!(child.wait().unwrap().success());
    runtime
        .block_on(SqliteStore::open(database.path()))
        .unwrap();
    let _ = fs::remove_file(ready);
    let _ = fs::remove_file(release);
}

#[test]
fn persistent_store_lock_holder() {
    let Some(database) = std::env::var_os(LOCK_HELPER_DATABASE) else {
        return;
    };
    let ready = PathBuf::from(std::env::var_os(LOCK_HELPER_READY).unwrap());
    let release = PathBuf::from(std::env::var_os(LOCK_HELPER_RELEASE).unwrap());
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let store = runtime.block_on(SqliteStore::open(database)).unwrap();
    fs::write(ready, b"ready").unwrap();

    let deadline = Instant::now() + Duration::from_secs(10);
    while !release.exists() {
        assert!(
            Instant::now() < deadline,
            "parent did not release the database lease in time"
        );
        thread::sleep(Duration::from_millis(10));
    }
    drop(store);
}

#[tokio::test]
async fn independent_memory_databases_do_not_share_the_file_lease() {
    let first = SqliteStore::open(":memory:").await.unwrap();
    let second = SqliteStore::open(":memory:").await.unwrap();
    first.readiness().await.unwrap();
    second.readiness().await.unwrap();
}

#[tokio::test]
async fn runtime_identity_is_immutable_and_mismatches_fail_closed() {
    let store = SqliteStore::open(":memory:").await.unwrap();
    let production = production_identity();
    store
        .bind_runtime_identity(production.clone())
        .await
        .unwrap();
    store.bind_runtime_identity(production).await.unwrap();

    let mut local = production_identity();
    local.profile = "local-development".into();
    local.environment = "local-development".into();
    local.primary_session_id = "session-ZR-DEV-1".into();
    local.primary_run_id = "ZR-DEV-1".into();
    local.policy_id = "local-development".into();
    local.policy_revision = "local-development/v1".into();
    assert!(matches!(
        store.bind_runtime_identity(local).await,
        Err(StorageError::RuntimeIdentityMismatch { .. })
    ));

    let mut newer_policy = production_identity();
    newer_policy.policy_revision = "production-guarded/v2".into();
    assert!(matches!(
        store.bind_runtime_identity(newer_policy).await,
        Err(StorageError::RuntimeIdentityMismatch { .. })
    ));
}

#[tokio::test]
async fn legacy_runtime_state_is_adopted_only_when_run_and_policy_match() {
    let compatible = SqliteStore::open(":memory:").await.unwrap();
    let (snapshot, events) = seed_fixture();
    compatible.seed_if_empty(snapshot, events).await.unwrap();
    compatible
        .bind_runtime_identity(production_identity())
        .await
        .unwrap();

    let mismatched = SqliteStore::open(":memory:").await.unwrap();
    let (snapshot, events) = seed_fixture();
    mismatched
        .seed_if_empty(snapshot.clone(), events)
        .await
        .unwrap();
    mismatched
        .commit_review(approved_dispatch_commit(&snapshot, "legacy-policy"))
        .await
        .unwrap();
    assert!(matches!(
        mismatched
            .bind_runtime_identity(production_identity())
            .await,
        Err(StorageError::RuntimeIdentityMismatch { .. })
    ));
}

#[tokio::test]
async fn memory_store_migrates_and_readiness_does_not_require_seed_data() {
    let store = SqliteStore::open(":memory:").await.unwrap();
    store.readiness().await.unwrap();
    assert!(matches!(
        store.snapshot(RUN_ID).await,
        Err(StorageError::RunNotFound(_))
    ));

    let (mut snapshot, events) = seed_fixture();
    snapshot.tool_policy = None;
    assert!(
        store
            .seed_if_empty(snapshot.clone(), events.clone())
            .await
            .unwrap()
    );
    let loaded = store.load_run(RUN_ID).await.unwrap();
    assert_eq!(loaded.snapshot, snapshot);
    assert_eq!(loaded.events, events);
}

#[tokio::test]
async fn seed_round_trips_mixed_v1_and_typed_v2_events() {
    let store = SqliteStore::open(":memory:").await.unwrap();
    let (snapshot, mut events) = seed_fixture();
    events[3].data = Some(RunEventData::ToolCallRequested {
        call: ToolCall {
            call_id: "read-metrics-001".into(),
            tool: "metrics.read".into(),
            tool_version: "1.0.0".into(),
            arguments: json!({"service": "checkout-api"}),
            arguments_digest: "sha256:read-metrics".into(),
            effect: ToolEffect::ReadOnly,
            sandbox_profile: SandboxProfile::ReadOnly,
            executor_status: ToolExecutorStatus::Available,
        },
        status: ToolCallStatus::Succeeded,
    });

    store
        .seed_if_empty(snapshot.clone(), events.clone())
        .await
        .unwrap();
    let loaded = store.load_run(RUN_ID).await.unwrap();
    assert_eq!(loaded.snapshot, snapshot);
    assert_eq!(loaded.events, events);
}

#[tokio::test]
async fn committed_review_and_receipt_survive_restart_without_reseeding() {
    let database = TestDatabase::new();
    let (seed_snapshot, seed_events) = seed_fixture();
    let commit = approved_commit(&seed_snapshot, "restart-review");

    {
        let store = SqliteStore::open(database.path()).await.unwrap();
        assert!(
            store
                .seed_if_empty(seed_snapshot.clone(), seed_events.clone())
                .await
                .unwrap()
        );
        assert_eq!(
            store.commit_review(commit.clone()).await.unwrap(),
            CommitOutcome::Committed
        );
    }

    let reopened = SqliteStore::open(database.path()).await.unwrap();
    reopened.readiness().await.unwrap();
    assert!(
        !reopened
            .seed_if_empty(seed_snapshot, seed_events)
            .await
            .unwrap()
    );
    let loaded = reopened.load_run(RUN_ID).await.unwrap();
    assert_eq!(loaded.snapshot.run.sequence, 7);
    assert_eq!(loaded.events.len(), 7);
    assert_eq!(loaded.events.last(), Some(&commit.event));

    let replay = reopened.commit_review(commit.clone()).await.unwrap();
    let CommitOutcome::Replayed(receipt) = replay else {
        panic!("restart retry must replay the committed receipt");
    };
    assert_eq!(receipt.request_fingerprint, commit.request_fingerprint);
    assert_eq!(receipt.response, commit.response);
}

#[tokio::test]
async fn same_key_is_idempotent_and_a_different_fingerprint_conflicts() {
    let store = seeded_memory_store().await;
    let (snapshot, _) = seed_fixture();
    let commit = approved_commit(&snapshot, "review-1");

    assert_eq!(
        store.commit_review(commit.clone()).await.unwrap(),
        CommitOutcome::Committed
    );
    assert!(matches!(
        store.commit_review(commit.clone()).await.unwrap(),
        CommitOutcome::Replayed(_)
    ));

    let mut conflicting = commit;
    conflicting.request_fingerprint =
        r#"{"decision":"reject","note":"ship it","run_id":"ZR-1842"}"#.into();
    assert!(matches!(
        store.commit_review(conflicting).await,
        Err(StorageError::IdempotencyConflict)
    ));
    assert_eq!(store.load_run(RUN_ID).await.unwrap().events.len(), 7);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_same_key_commits_once_and_replays_the_rest() {
    let database = TestDatabase::new();
    let store = seeded_file_store(database.path()).await;
    let (snapshot, _) = seed_fixture();
    let commit = approved_commit(&snapshot, "concurrent-same-key");

    let mut tasks = Vec::new();
    for _ in 0..8 {
        let store = store.clone();
        let commit = commit.clone();
        tasks.push(tokio::spawn(
            async move { store.commit_review(commit).await },
        ));
    }

    let mut committed = 0;
    let mut replayed = 0;
    for task in tasks {
        match task.await.unwrap().unwrap() {
            CommitOutcome::Committed => committed += 1,
            CommitOutcome::Replayed(_) => replayed += 1,
        }
    }
    assert_eq!(committed, 1);
    assert_eq!(replayed, 7);
    assert_eq!(store.load_run(RUN_ID).await.unwrap().events.len(), 7);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn different_keys_use_run_head_cas_for_first_wins_settlement() {
    let database = TestDatabase::new();
    let store = seeded_file_store(database.path()).await;
    let (snapshot, _) = seed_fixture();
    let first = approved_commit(&snapshot, "cas-a");
    let mut second = first.clone();
    second.idempotency_key = "cas-b".into();

    let left = tokio::spawn({
        let store = store.clone();
        async move { store.commit_review(first).await }
    });
    let right = tokio::spawn({
        let store = store.clone();
        async move { store.commit_review(second).await }
    });
    let outcomes = [left.await.unwrap(), right.await.unwrap()];
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| matches!(outcome, Ok(CommitOutcome::Committed)))
            .count(),
        1
    );
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| matches!(outcome, Err(StorageError::ConcurrentModification)))
            .count(),
        1
    );
    assert_eq!(store.load_run(RUN_ID).await.unwrap().events.len(), 7);
}

#[tokio::test]
async fn failure_after_event_insert_rolls_back_projection_event_and_receipt() {
    let store = seeded_memory_store().await;
    let (snapshot, _) = seed_fixture();
    let commit = approved_dispatch_commit(&snapshot, "atomic-review");

    assert!(matches!(
        store.commit_review_with_failure(commit.clone()).await,
        Err(StorageError::InjectedFailure)
    ));
    let unchanged = store.load_run(RUN_ID).await.unwrap();
    assert_eq!(unchanged.snapshot.run.sequence, 6);
    assert_eq!(unchanged.events.len(), 6);
    assert!(
        store
            .review_receipt("atomic-review")
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        store
            .dispatch_job("call-local-001")
            .await
            .unwrap()
            .is_none()
    );

    assert_eq!(
        store.commit_review(commit).await.unwrap(),
        CommitOutcome::Committed
    );
}

#[tokio::test]
async fn v1_database_migrates_in_place_and_preserves_event_foreign_keys() {
    let database = TestDatabase::new();
    create_v1_database(database.path());

    let store = SqliteStore::open(database.path()).await.unwrap();
    store.readiness().await.unwrap();
    let loaded = store.load_run(RUN_ID).await.unwrap();
    assert_eq!(loaded.snapshot.run.status, RunStatus::NeedsAttention);
    assert_eq!(loaded.snapshot.run.sequence, 6);
    assert_eq!(loaded.events.len(), 6);
    assert!(store.peek_next_dispatch().await.unwrap().is_none());

    let connection = rusqlite::Connection::open(database.path()).unwrap();
    connection
        .pragma_update(None, "foreign_keys", true)
        .unwrap();
    let versions = connection
        .prepare("SELECT version FROM schema_migrations ORDER BY version")
        .unwrap()
        .query_map([], |row| row.get::<_, i64>(0))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(versions, vec![1, 2, 3, 4]);
    let run_event_parent: String = connection
        .query_row(
            "SELECT \"table\" FROM pragma_foreign_key_list('run_events') LIMIT 1",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(run_event_parent, "runs");
    let invalid_insert = connection.execute(
        r#"INSERT INTO run_events(
               run_id, sequence, event_id, event_kind, payload_version, payload_json
           ) VALUES ('missing-run', 1, 'impossible', 'system', 1, '{}')"#,
        [],
    );
    assert!(invalid_insert.is_err());

    let session = store.get_session("session-ZR-1842").await.unwrap();
    assert_eq!(session.session.title, "Checkout API latency");
    assert_eq!(session.session.status, SessionStatus::Ready);
    assert_eq!(session.session.sequence, 2);
    assert_eq!(session.run_ids, vec![RUN_ID]);
    assert!(matches!(
        session.events[0].data,
        SessionEventData::SessionCreated { .. }
    ));
    assert!(matches!(
        session.events[1].data,
        SessionEventData::RunAttached { .. }
    ));
}

#[tokio::test]
async fn v3_runtime_identity_migrates_with_primary_session_and_allows_other_runs() {
    let database = TestDatabase::new();
    create_v3_database_with_identity(database.path());
    insert_second_run(database.path());

    let store = SqliteStore::open(database.path()).await.unwrap();
    store
        .bind_runtime_identity(production_identity())
        .await
        .unwrap();
    let connection = rusqlite::Connection::open(database.path()).unwrap();
    let (session_id, run_id): (String, String) = connection
        .query_row(
            "SELECT primary_session_id, primary_run_id FROM runtime_identity WHERE singleton = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(session_id, "session-ZR-1842");
    assert_eq!(run_id, RUN_ID);
}

#[tokio::test]
async fn unbound_runtime_identity_selects_a_primary_without_rejecting_other_runs() {
    let database = TestDatabase::new();
    create_v1_database(database.path());
    let store = SqliteStore::open(database.path()).await.unwrap();
    insert_second_run(database.path());

    store
        .bind_runtime_identity(production_identity())
        .await
        .unwrap();
    assert!(store.snapshot("ZR-SECOND").await.is_ok());
    assert_eq!(store.list_sessions().await.unwrap().len(), 1);
}

#[tokio::test]
async fn demo_session_seed_creates_and_attaches_once_without_rewriting_history() {
    let store = seeded_memory_store().await;
    assert!(
        store
            .seed_demo_session("session-ZR-1842", "Checkout API latency", RUN_ID)
            .await
            .unwrap()
    );
    assert!(
        !store
            .seed_demo_session("session-ZR-1842", "A different startup label", RUN_ID)
            .await
            .unwrap()
    );

    let detail = store.get_session("session-ZR-1842").await.unwrap();
    assert_eq!(detail.session.title, "Checkout API latency");
    assert_eq!(detail.session.sequence, 2);
    assert_eq!(detail.events.len(), 2);
    assert_eq!(detail.run_ids, vec![RUN_ID]);
}

#[tokio::test]
async fn create_list_get_and_receipt_replay_are_durable_and_conflict_safe() {
    let database = TestDatabase::new();
    let request = CreateSessionRequest {
        id: "session-alpha".into(),
        title: "Alpha conversation".into(),
    };
    {
        let store = SqliteStore::open(database.path()).await.unwrap();
        let created = store
            .create_session(request.clone(), "create-alpha")
            .await
            .unwrap();
        assert!(!created.replayed);
        assert_eq!(created.session.sequence, 1);
        assert_eq!(created.event.sequence, 1);

        let replay = store
            .create_session(request.clone(), "create-alpha")
            .await
            .unwrap();
        assert!(replay.replayed);
        assert_eq!(replay.event, created.event);

        let mut conflicting = request.clone();
        conflicting.title = "Different input".into();
        assert!(matches!(
            store.create_session(conflicting, "create-alpha").await,
            Err(StorageError::IdempotencyConflict)
        ));
        assert_eq!(store.list_sessions().await.unwrap().len(), 1);
    }

    let reopened = SqliteStore::open(database.path()).await.unwrap();
    let detail = reopened.get_session(&request.id).await.unwrap();
    assert_eq!(detail.session.title, request.title);
    assert_eq!(detail.events.len(), 1);
    assert!(matches!(
        detail.events[0].data,
        SessionEventData::SessionCreated { .. }
    ));
    assert!(
        reopened
            .create_session(request, "create-alpha")
            .await
            .unwrap()
            .replayed
    );
}

#[tokio::test]
async fn start_and_flush_commit_contiguous_events_projection_ack_and_receipts() {
    let store = created_session_store().await;
    let start_request = StartTurnRequest {
        turn_id: "turn-1".into(),
        user_message: "Investigate the incident".into(),
        expected_sequence: 1,
    };
    let started = store
        .start_turn("session-alpha", start_request.clone(), "start-1")
        .await
        .unwrap();
    assert_eq!(started.session.status, SessionStatus::Running);
    assert_eq!(started.session.sequence, 2);
    assert_eq!(started.turn.status, SessionTurnStatus::Open);
    assert_eq!(started.event.sequence, 2);
    assert!(matches!(
        started.event.data,
        SessionEventData::UserMessage { .. }
    ));
    assert!(
        store
            .start_turn("session-alpha", start_request.clone(), "start-1")
            .await
            .unwrap()
            .replayed
    );
    let mut conflicting_start = start_request;
    conflicting_start.user_message = "Different message".into();
    assert!(matches!(
        store
            .start_turn("session-alpha", conflicting_start, "start-1")
            .await,
        Err(StorageError::IdempotencyConflict)
    ));

    let flush_request = FlushSessionRequest {
        turn_id: "turn-1".into(),
        assistant_message: Some("The durable diagnosis is complete.".into()),
        expected_sequence: 2,
    };
    let flushed = store
        .flush_turn("session-alpha", flush_request.clone(), "flush-1")
        .await
        .unwrap();
    assert_eq!(flushed.session.status, SessionStatus::Ready);
    assert_eq!(flushed.session.sequence, 4);
    assert_eq!(flushed.turn.status, SessionTurnStatus::Flushed);
    assert_eq!(
        flushed.turn.assistant_message.as_deref(),
        Some("The durable diagnosis is complete.")
    );
    assert_eq!(flushed.events.len(), 2);
    assert!(matches!(
        flushed.events[0].data,
        SessionEventData::AssistantMessage { .. }
    ));
    assert!(matches!(
        flushed.events[1].data,
        SessionEventData::TurnFlushed { .. }
    ));
    assert_eq!(flushed.ack.durability_sequence, 4);
    assert!(
        store
            .flush_turn("session-alpha", flush_request, "flush-1")
            .await
            .unwrap()
            .replayed
    );

    let detail = store.get_session("session-alpha").await.unwrap();
    assert_eq!(
        detail
            .events
            .iter()
            .map(|event| event.sequence)
            .collect::<Vec<_>>(),
        vec![1, 2, 3, 4]
    );
    assert!(matches!(
        store
            .resume_session(
                "session-alpha",
                ResumeSessionRequest {
                    expected_sequence: 2
                },
                "stale-resume",
            )
            .await,
        Err(StorageError::ConcurrentModification)
    ));
    assert!(matches!(
        store
            .resume_session(
                "session-alpha",
                ResumeSessionRequest {
                    expected_sequence: 4
                },
                "ready-resume",
            )
            .await,
        Err(StorageError::InvalidSessionTransition(_))
    ));
}

#[tokio::test]
async fn flush_failure_rolls_back_message_turn_projection_event_and_receipt() {
    let store = created_session_store().await;
    store
        .start_turn(
            "session-alpha",
            StartTurnRequest {
                turn_id: "turn-atomic".into(),
                user_message: "Keep this open".into(),
                expected_sequence: 1,
            },
            "start-atomic",
        )
        .await
        .unwrap();
    let request = FlushSessionRequest {
        turn_id: "turn-atomic".into(),
        assistant_message: Some("must roll back".into()),
        expected_sequence: 2,
    };
    assert!(matches!(
        store
            .flush_turn_with_failure("session-alpha", request.clone(), "flush-atomic")
            .await,
        Err(StorageError::InjectedFailure)
    ));
    let unchanged = store.get_session("session-alpha").await.unwrap();
    assert_eq!(unchanged.session.status, SessionStatus::Running);
    assert_eq!(unchanged.session.sequence, 2);
    assert_eq!(unchanged.turns[0].status, SessionTurnStatus::Open);
    assert_eq!(unchanged.turns[0].assistant_message, None);
    assert_eq!(unchanged.events.len(), 2);

    let committed = store
        .flush_turn("session-alpha", request, "flush-atomic")
        .await
        .unwrap();
    assert_eq!(committed.ack.durability_sequence, 4);
}

#[tokio::test]
async fn open_turn_restart_recovery_appends_interrupted_never_flush_and_requires_resume() {
    let database = TestDatabase::new();
    {
        let store = SqliteStore::open(database.path()).await.unwrap();
        store
            .create_session(alpha_session_request(), "create-recovery")
            .await
            .unwrap();
        store
            .start_turn(
                "session-alpha",
                StartTurnRequest {
                    turn_id: "turn-recovery".into(),
                    user_message: "This process may stop".into(),
                    expected_sequence: 1,
                },
                "start-recovery",
            )
            .await
            .unwrap();
    }

    let reopened = SqliteStore::open(database.path()).await.unwrap();
    let recovered = reopened.recover_open_turns().await.unwrap();
    assert_eq!(recovered.len(), 1);
    assert_eq!(recovered[0].sequence, 3);
    assert!(matches!(
        recovered[0].data,
        SessionEventData::TurnInterrupted { .. }
    ));
    assert!(reopened.recover_open_turns().await.unwrap().is_empty());

    let detail = reopened.get_session("session-alpha").await.unwrap();
    assert_eq!(detail.session.status, SessionStatus::NeedsAttention);
    assert_eq!(detail.session.sequence, 3);
    assert_eq!(detail.turns[0].status, SessionTurnStatus::Interrupted);
    assert!(
        detail
            .events
            .iter()
            .all(|event| !matches!(event.data, SessionEventData::TurnFlushed { .. }))
    );
    assert!(matches!(
        reopened
            .start_turn(
                "session-alpha",
                StartTurnRequest {
                    turn_id: "turn-too-early".into(),
                    user_message: "must resume first".into(),
                    expected_sequence: 3,
                },
                "start-too-early",
            )
            .await,
        Err(StorageError::InvalidSessionTransition(_))
    ));

    let resume_request = ResumeSessionRequest {
        expected_sequence: 3,
    };
    let resumed = reopened
        .resume_session("session-alpha", resume_request.clone(), "resume-recovery")
        .await
        .unwrap();
    assert_eq!(resumed.session.status, SessionStatus::Ready);
    assert_eq!(resumed.session.sequence, 4);
    assert!(matches!(
        resumed.event.data,
        SessionEventData::SessionResumed {
            from_status: SessionStatus::NeedsAttention
        }
    ));
    assert!(
        reopened
            .resume_session("session-alpha", resume_request, "resume-recovery")
            .await
            .unwrap()
            .replayed
    );
}

#[tokio::test]
async fn startup_recovery_interrupts_each_open_turn_once() {
    let store = created_session_store().await;
    store
        .create_session(
            CreateSessionRequest {
                id: "session-beta".into(),
                title: "Beta conversation".into(),
            },
            "create-beta",
        )
        .await
        .unwrap();
    for (session_id, turn_id, key) in [
        ("session-alpha", "turn-alpha", "start-alpha"),
        ("session-beta", "turn-beta", "start-beta"),
    ] {
        store
            .start_turn(
                session_id,
                StartTurnRequest {
                    turn_id: turn_id.into(),
                    user_message: "open".into(),
                    expected_sequence: 1,
                },
                key,
            )
            .await
            .unwrap();
    }

    let events = store.recover_open_turns().await.unwrap();
    assert_eq!(events.len(), 2);
    assert!(
        events
            .iter()
            .all(|event| matches!(event.data, SessionEventData::TurnInterrupted { .. }))
    );
    assert!(store.recover_open_turns().await.unwrap().is_empty());
    for session_id in ["session-alpha", "session-beta"] {
        let detail = store.get_session(session_id).await.unwrap();
        assert_eq!(detail.session.status, SessionStatus::NeedsAttention);
        assert_eq!(detail.turns[0].status, SessionTurnStatus::Interrupted);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_session_commands_use_receipt_replay_and_sequence_cas() {
    let database = TestDatabase::new();
    let store = SqliteStore::open(database.path()).await.unwrap();
    store
        .create_session(alpha_session_request(), "create-concurrent-session")
        .await
        .unwrap();
    let request = StartTurnRequest {
        turn_id: "turn-shared".into(),
        user_message: "exactly once".into(),
        expected_sequence: 1,
    };
    let mut tasks = Vec::new();
    for _ in 0..8 {
        let store = store.clone();
        let request = request.clone();
        tasks.push(tokio::spawn(async move {
            store
                .start_turn("session-alpha", request, "start-shared")
                .await
        }));
    }
    let mut originals = 0;
    let mut replays = 0;
    for task in tasks {
        let response = task.await.unwrap().unwrap();
        if response.replayed {
            replays += 1;
        } else {
            originals += 1;
        }
    }
    assert_eq!(originals, 1);
    assert_eq!(replays, 7);
    assert_eq!(
        store
            .get_session("session-alpha")
            .await
            .unwrap()
            .events
            .len(),
        2
    );

    store
        .flush_turn(
            "session-alpha",
            FlushSessionRequest {
                turn_id: "turn-shared".into(),
                assistant_message: None,
                expected_sequence: 2,
            },
            "flush-shared",
        )
        .await
        .unwrap();
    let left = tokio::spawn({
        let store = store.clone();
        async move {
            store
                .start_turn(
                    "session-alpha",
                    StartTurnRequest {
                        turn_id: "turn-left".into(),
                        user_message: "left".into(),
                        expected_sequence: 3,
                    },
                    "start-left",
                )
                .await
        }
    });
    let right = tokio::spawn({
        let store = store.clone();
        async move {
            store
                .start_turn(
                    "session-alpha",
                    StartTurnRequest {
                        turn_id: "turn-right".into(),
                        user_message: "right".into(),
                        expected_sequence: 3,
                    },
                    "start-right",
                )
                .await
        }
    });
    let outcomes = [left.await.unwrap(), right.await.unwrap()];
    assert_eq!(outcomes.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        outcomes
            .iter()
            .filter(|result| matches!(result, Err(StorageError::ConcurrentModification)))
            .count(),
        1
    );
    let detail = store.get_session("session-alpha").await.unwrap();
    assert_eq!(detail.session.sequence, 4);
    assert_eq!(detail.events.len(), 4);
}

#[tokio::test]
async fn one_session_can_own_multiple_runs_but_each_run_has_one_owner() {
    let database = TestDatabase::new();
    let store = seeded_file_store(database.path()).await;
    store
        .seed_demo_session("session-ZR-1842", "Checkout API latency", RUN_ID)
        .await
        .unwrap();
    insert_second_run(database.path());

    let attached = store
        .attach_run(
            "session-ZR-1842",
            AttachRunRequest {
                run_id: "ZR-SECOND".into(),
                expected_sequence: 2,
            },
            "attach-second",
        )
        .await
        .unwrap();
    assert_eq!(attached.session.sequence, 3);
    assert!(
        store
            .attach_run(
                "session-ZR-1842",
                AttachRunRequest {
                    run_id: "ZR-SECOND".into(),
                    expected_sequence: 2,
                },
                "attach-second",
            )
            .await
            .unwrap()
            .replayed
    );
    assert!(matches!(
        store
            .attach_run(
                "session-ZR-1842",
                AttachRunRequest {
                    run_id: "ZR-SECOND".into(),
                    expected_sequence: 3,
                },
                "attach-second",
            )
            .await,
        Err(StorageError::IdempotencyConflict)
    ));
    let detail = store.get_session("session-ZR-1842").await.unwrap();
    assert_eq!(detail.run_ids, vec![RUN_ID, "ZR-SECOND"]);

    store
        .create_session(
            CreateSessionRequest {
                id: "session-other".into(),
                title: "Other".into(),
            },
            "create-other",
        )
        .await
        .unwrap();
    assert!(matches!(
        store
            .attach_run(
                "session-other",
                AttachRunRequest {
                    run_id: "ZR-SECOND".into(),
                    expected_sequence: 1,
                },
                "attach-second-again",
            )
            .await,
        Err(StorageError::RunAlreadyAttached { .. })
    ));
}

#[tokio::test]
async fn session_ledger_turns_and_run_ownership_are_append_only() {
    let database = TestDatabase::new();
    let store = seeded_file_store(database.path()).await;
    store
        .seed_demo_session("session-ZR-1842", "Checkout API latency", RUN_ID)
        .await
        .unwrap();
    store
        .start_turn(
            "session-ZR-1842",
            StartTurnRequest {
                turn_id: "turn-immutable".into(),
                user_message: "immutable input".into(),
                expected_sequence: 2,
            },
            "start-immutable",
        )
        .await
        .unwrap();

    let connection = rusqlite::Connection::open(database.path()).unwrap();
    assert!(
        connection
            .execute("DELETE FROM session_events", [])
            .is_err()
    );
    assert!(
        connection
            .execute(
                "UPDATE session_events SET event_kind = 'session_resumed' WHERE session_id = ?1",
                ["session-ZR-1842"],
            )
            .is_err()
    );
    assert!(connection.execute("DELETE FROM session_runs", []).is_err());
    assert!(
        connection
            .execute("DELETE FROM session_command_receipts", [])
            .is_err()
    );
    assert!(
        connection
            .execute(
                "UPDATE session_turns SET user_message = 'changed' WHERE id = 'turn-immutable'",
                [],
            )
            .is_err()
    );
}

#[tokio::test]
async fn approval_projection_receipt_and_dispatch_enqueue_commit_atomically() {
    let store = seeded_memory_store().await;
    let (snapshot, _) = seed_fixture();
    let commit = approved_dispatch_commit(&snapshot, "approve-enqueue");

    assert_eq!(
        store.commit_review(commit.clone()).await.unwrap(),
        CommitOutcome::Committed
    );
    let loaded = store.load_run(RUN_ID).await.unwrap();
    assert_eq!(loaded.snapshot.run.status, RunStatus::Queued);
    assert_eq!(loaded.snapshot.run.sequence, 7);
    assert_eq!(loaded.events.len(), 7);
    assert!(loaded.events.last().unwrap().data.is_some());

    let queued = store.dispatch_job("call-local-001").await.unwrap().unwrap();
    assert_eq!(queued.status, DispatchStatus::Queued);
    assert_eq!(queued.attempt, 0);
    assert_eq!(queued.approval_event_sequence, 7);
    assert_eq!(queued.result_json, None);
    assert_eq!(store.peek_next_dispatch().await.unwrap().unwrap(), queued);

    assert!(matches!(
        store.commit_review(commit).await.unwrap(),
        CommitOutcome::Replayed(_)
    ));
    assert_eq!(store.load_run(RUN_ID).await.unwrap().events.len(), 7);
}

#[tokio::test]
async fn database_rejects_dispatch_input_mutation_deletion_and_state_skips() {
    let database = TestDatabase::new();
    let store = seeded_file_store(database.path()).await;
    let (snapshot, _) = seed_fixture();
    store
        .commit_review(approved_dispatch_commit(&snapshot, "immutable-job"))
        .await
        .unwrap();

    let connection = rusqlite::Connection::open(database.path()).unwrap();
    assert!(
        connection
            .execute(
                "UPDATE dispatch_jobs SET args_json = '{}' WHERE call_id = ?1",
                ["call-local-001"],
            )
            .is_err()
    );
    assert!(
        connection
            .execute(
                "UPDATE dispatch_jobs SET status = 'finished' WHERE call_id = ?1",
                ["call-local-001"],
            )
            .is_err()
    );
    assert!(
        connection
            .execute(
                "DELETE FROM dispatch_jobs WHERE call_id = ?1",
                ["call-local-001"],
            )
            .is_err()
    );
    assert_eq!(
        store
            .dispatch_job("call-local-001")
            .await
            .unwrap()
            .unwrap()
            .status,
        DispatchStatus::Queued
    );
}

#[tokio::test]
async fn claim_is_queue_ordered_and_atomically_appends_the_start_event() {
    let store = seeded_memory_store().await;
    let (snapshot, _) = seed_fixture();
    let review = approved_dispatch_commit(&snapshot, "claim-review");
    store.commit_review(review.clone()).await.unwrap();
    let start = start_commit(&review.snapshot);

    let ClaimOutcome::Claimed(claimed) = store.claim_next_dispatch(start.clone()).await.unwrap()
    else {
        panic!("the durable queue head must be claimable");
    };
    assert_eq!(claimed.status, DispatchStatus::Started);
    assert_eq!(claimed.attempt, 1);
    assert_eq!(claimed.start_event_sequence, Some(8));
    assert!(claimed.started_at.is_some());
    assert!(store.peek_next_dispatch().await.unwrap().is_none());

    let loaded = store.load_run(RUN_ID).await.unwrap();
    assert_eq!(loaded.snapshot.run.status, RunStatus::Running);
    assert_eq!(loaded.snapshot.run.sequence, 8);
    assert_eq!(loaded.events.last(), Some(&start.event));
    assert_eq!(
        store.claim_next_dispatch(start).await.unwrap(),
        ClaimOutcome::NotAvailable
    );
}

#[tokio::test]
async fn claim_failure_rolls_back_job_projection_and_v2_event() {
    let store = seeded_memory_store().await;
    let (snapshot, _) = seed_fixture();
    let review = approved_dispatch_commit(&snapshot, "claim-rollback-review");
    store.commit_review(review.clone()).await.unwrap();
    let start = start_commit(&review.snapshot);

    assert!(matches!(
        store.claim_next_dispatch_with_failure(start.clone()).await,
        Err(StorageError::InjectedFailure)
    ));
    let job = store.dispatch_job("call-local-001").await.unwrap().unwrap();
    assert_eq!(job.status, DispatchStatus::Queued);
    assert_eq!(job.attempt, 0);
    let loaded = store.load_run(RUN_ID).await.unwrap();
    assert_eq!(loaded.snapshot.run.sequence, 7);
    assert_eq!(loaded.events.len(), 7);

    assert!(matches!(
        store.claim_next_dispatch(start).await.unwrap(),
        ClaimOutcome::Claimed(_)
    ));
}

#[tokio::test]
async fn complete_is_atomic_and_persists_the_typed_result() {
    let store = seeded_memory_store().await;
    let (snapshot, _) = seed_fixture();
    let review = approved_dispatch_commit(&snapshot, "complete-review");
    store.commit_review(review.clone()).await.unwrap();
    let start = start_commit(&review.snapshot);
    store.claim_next_dispatch(start.clone()).await.unwrap();
    let completion = completion_commit(&start.snapshot);

    assert!(matches!(
        store
            .complete_dispatch_with_failure(completion.clone())
            .await,
        Err(StorageError::InjectedFailure)
    ));
    let still_started = store.dispatch_job("call-local-001").await.unwrap().unwrap();
    assert_eq!(still_started.status, DispatchStatus::Started);
    assert_eq!(still_started.result_json, None);
    assert_eq!(store.load_run(RUN_ID).await.unwrap().events.len(), 8);

    let finished = store.complete_dispatch(completion.clone()).await.unwrap();
    assert_eq!(finished.status, DispatchStatus::Finished);
    assert_eq!(finished.result_json, Some(completion.result_json));
    assert_eq!(finished.result_event_sequence, Some(9));
    assert!(finished.finished_at.is_some());
    let loaded = store.load_run(RUN_ID).await.unwrap();
    assert_eq!(loaded.snapshot.run.status, RunStatus::Succeeded);
    assert_eq!(loaded.events.last(), Some(&completion.event));
}

#[tokio::test]
async fn queued_job_survives_restart_and_remains_dispatchable() {
    let database = TestDatabase::new();
    let (snapshot, events) = seed_fixture();
    let review = approved_dispatch_commit(&snapshot, "restart-queued");
    {
        let store = SqliteStore::open(database.path()).await.unwrap();
        store.seed_if_empty(snapshot, events).await.unwrap();
        store.commit_review(review.clone()).await.unwrap();
    }

    let reopened = SqliteStore::open(database.path()).await.unwrap();
    let queued = reopened.peek_next_dispatch().await.unwrap().unwrap();
    assert_eq!(queued.call_id, "call-local-001");
    assert_eq!(queued.status, DispatchStatus::Queued);
    assert!(matches!(
        reopened
            .claim_next_dispatch(start_commit(&review.snapshot))
            .await
            .unwrap(),
        ClaimOutcome::Claimed(_)
    ));
}

#[tokio::test]
async fn started_job_restart_recovery_records_outcome_unknown_without_requeue() {
    let database = TestDatabase::new();
    let (snapshot, events) = seed_fixture();
    let review = approved_dispatch_commit(&snapshot, "restart-started");
    let start = start_commit(&review.snapshot);
    {
        let store = SqliteStore::open(database.path()).await.unwrap();
        store.seed_if_empty(snapshot, events).await.unwrap();
        store.commit_review(review).await.unwrap();
        store.claim_next_dispatch(start.clone()).await.unwrap();
    }

    let reopened = SqliteStore::open(database.path()).await.unwrap();
    let started = reopened.started_dispatches().await.unwrap();
    assert_eq!(started.len(), 1);
    assert_eq!(started[0].status, DispatchStatus::Started);
    assert!(reopened.peek_next_dispatch().await.unwrap().is_none());

    let recovery = recovery_commit(&start.snapshot);
    let recovered = reopened.recover_started(recovery.clone()).await.unwrap();
    assert_eq!(recovered.status, DispatchStatus::Finished);
    assert_eq!(recovered.result_json, Some(recovery.result_json));
    assert!(reopened.started_dispatches().await.unwrap().is_empty());
    assert!(reopened.peek_next_dispatch().await.unwrap().is_none());
    let loaded = reopened.load_run(RUN_ID).await.unwrap();
    assert_eq!(loaded.snapshot.run.status, RunStatus::NeedsAttention);
    assert_eq!(loaded.snapshot.run.sequence, 9);
    assert_eq!(loaded.events.last(), Some(&recovery.event));

    drop(reopened);
    let reopened_again = SqliteStore::open(database.path()).await.unwrap();
    assert!(
        reopened_again
            .started_dispatches()
            .await
            .unwrap()
            .is_empty()
    );
    assert!(reopened_again.peek_next_dispatch().await.unwrap().is_none());
}

#[tokio::test]
async fn event_reader_fails_closed_on_unknown_kind_and_payload_version() {
    let kind_database = TestDatabase::new();
    let kind_store = seeded_file_store(kind_database.path()).await;
    insert_raw_event(kind_database.path(), "future_event", 1);
    assert!(matches!(
        kind_store.events_after(RUN_ID, 6).await,
        Err(StorageError::UnsupportedEventKind(kind)) if kind == "future_event"
    ));

    let version_database = TestDatabase::new();
    let version_store = seeded_file_store(version_database.path()).await;
    insert_raw_event(version_database.path(), "approval", 99);
    assert!(matches!(
        version_store.events_after(RUN_ID, 6).await,
        Err(StorageError::UnsupportedPayloadVersion { version: 99, .. })
    ));
}

async fn seeded_memory_store() -> SqliteStore {
    let store = SqliteStore::open(":memory:").await.unwrap();
    let (snapshot, events) = seed_fixture();
    assert!(store.seed_if_empty(snapshot, events).await.unwrap());
    store
}

fn alpha_session_request() -> CreateSessionRequest {
    CreateSessionRequest {
        id: "session-alpha".into(),
        title: "Alpha conversation".into(),
    }
}

async fn created_session_store() -> SqliteStore {
    let store = SqliteStore::open(":memory:").await.unwrap();
    store
        .create_session(alpha_session_request(), "create-session-alpha")
        .await
        .unwrap();
    store
}

fn production_identity() -> RuntimeIdentity {
    RuntimeIdentity {
        profile: "production-guarded".into(),
        environment: "production".into(),
        primary_session_id: "session-ZR-1842".into(),
        primary_run_id: RUN_ID.into(),
        policy_id: "production-guarded".into(),
        policy_revision: "production-guarded/v1".into(),
    }
}

async fn seeded_file_store(path: &Path) -> SqliteStore {
    let store = SqliteStore::open(path).await.unwrap();
    let (snapshot, events) = seed_fixture();
    assert!(store.seed_if_empty(snapshot, events).await.unwrap());
    store
}

fn seed_fixture() -> (RunSnapshot, Vec<RunEvent>) {
    let mut events = vec![
        event(1, EventType::User, "User report received"),
        event(2, EventType::Reasoning, "Hypothesis formed"),
        event(3, EventType::Step, "Diagnostics selected"),
        event(4, EventType::ToolCall, "Telemetry collected"),
        event(5, EventType::Evidence, "Pressure correlated"),
    ];
    events.push(RunEvent {
        sequence: 6,
        id: "evt-000006".into(),
        turn: 1,
        step: 4,
        event_type: EventType::Approval,
        title: "Production change awaiting review".into(),
        at: "2026-08-26T01:19:02Z".into(),
        summary: Some("Approve or reject the guarded change.".into()),
        content: Some("Increase the connection ceiling from 80 to 120.".into()),
        metadata: BTreeMap::from([("effect".into(), json!("production_write"))]),
        approval: Some(Approval {
            id: "APR-901".into(),
            status: ApprovalStatus::Pending,
            action: "update connection ceiling".into(),
            tool: "rds.connection_limit.update".into(),
            change: "connections: 80 -> 120".into(),
            requires_approval: true,
            call_id: None,
            policy_revision: None,
            arguments_digest: None,
            sandbox_profile: None,
            scope: None,
        }),
        data: None,
    });

    let snapshot = RunSnapshot {
        incident: IncidentSummary {
            id: "INC-2048".into(),
            title: "Checkout API latency".into(),
            severity: Severity::Critical,
            status: IncidentStatus::Mitigating,
            service: "checkout-api".into(),
            region: "us-east-1".into(),
            user_impact: "Checkout p95 is 4.8 s".into(),
            since: "2026-08-26T01:16:00Z".into(),
        },
        run: RunSummary {
            id: RUN_ID.into(),
            status: RunStatus::WaitingForApproval,
            environment: "production".into(),
            started_at: "2026-08-26T01:18:00Z".into(),
            duration_seconds: 62,
            agent: "Zeus Responder".into(),
            sequence: 6,
        },
        metrics: vec![
            Metric {
                label: "Checkout p95".into(),
                value: "4.8".into(),
                unit: Some("s".into()),
                trend: Some("+3.6 s".into()),
                tone: Some(MetricTone::Critical),
            },
            Metric {
                label: "Pending approvals".into(),
                value: "1".into(),
                unit: None,
                trend: None,
                tone: Some(MetricTone::Warning),
            },
        ],
        evidence: vec![EvidenceSummary {
            id: "EVD-301".into(),
            at: "01:18:31Z".into(),
            label: "RDS connections at 92%".into(),
            source: "aws.rds.describe".into(),
        }],
        tool_policy: Some(ToolPolicySummary {
            name: "Production guarded".into(),
            allows: vec!["Read metrics".into()],
            requires_approval: vec!["Change RDS limits".into()],
            denies: vec!["Delete database".into()],
        }),
    };
    (snapshot, events)
}

fn event(sequence: u64, event_type: EventType, title: &str) -> RunEvent {
    RunEvent {
        sequence,
        id: format!("evt-{sequence:06}"),
        turn: 1,
        step: sequence.saturating_sub(2) as u32,
        event_type,
        title: title.into(),
        at: format!("2026-08-26T01:18:{sequence:02}Z"),
        summary: Some(title.into()),
        content: None,
        metadata: BTreeMap::new(),
        approval: None,
        data: None,
    }
}

fn approved_commit(seed: &RunSnapshot, key: &str) -> ReviewCommit {
    let mut snapshot = seed.clone();
    snapshot.run.status = RunStatus::Active;
    snapshot.run.sequence = 7;
    if let Some(metric) = snapshot
        .metrics
        .iter_mut()
        .find(|metric| metric.label == "Pending approvals")
    {
        metric.value = "0".into();
    }
    let event = RunEvent {
        sequence: 7,
        id: "evt-000007".into(),
        turn: 1,
        step: 4,
        event_type: EventType::Approval,
        title: "Production change approved".into(),
        at: "2026-08-26T01:20:00Z".into(),
        summary: Some("The guarded change may now be dispatched.".into()),
        content: Some("ship it".into()),
        metadata: BTreeMap::from([("durable".into(), json!(true))]),
        approval: Some(Approval {
            id: "APR-901".into(),
            status: ApprovalStatus::Approved,
            action: "update connection ceiling".into(),
            tool: "rds.connection_limit.update".into(),
            change: "connections: 80 -> 120".into(),
            requires_approval: true,
            call_id: None,
            policy_revision: None,
            arguments_digest: None,
            sandbox_profile: None,
            scope: None,
        }),
        data: None,
    };
    let response = ReviewResponse {
        run: snapshot.run.clone(),
        event: event.clone(),
        replayed: false,
    };
    ReviewCommit {
        expected_sequence: seed.run.sequence,
        snapshot,
        event,
        idempotency_key: key.into(),
        request_fingerprint: r#"{"decision":"approve","note":"ship it","run_id":"ZR-1842"}"#.into(),
        response,
        dispatch: None,
    }
}

fn approved_dispatch_commit(seed: &RunSnapshot, key: &str) -> ReviewCommit {
    let mut commit = approved_commit(seed, key);
    let dispatch = DispatchJobSpec {
        call_id: "call-local-001".into(),
        approval_id: "APR-901".into(),
        tool_name: "local.echo".into(),
        tool_version: "1.0.0".into(),
        effect: ToolEffect::LocalWrite,
        args_json: json!({"message": "raise the local fixture ceiling"}),
        args_digest: "sha256:args-local-001".into(),
        policy_id: "local-alpha".into(),
        policy_revision: "rev-2026-08-26".into(),
        sandbox_profile: SandboxProfile::WorkspaceWrite,
    };
    commit.snapshot.run.status = RunStatus::Queued;
    let approval = commit
        .event
        .approval
        .as_mut()
        .expect("review fixture has an approval");
    approval.tool = dispatch.tool_name.clone();
    approval.call_id = Some(dispatch.call_id.clone());
    approval.policy_revision = Some(dispatch.policy_revision.clone());
    approval.arguments_digest = Some(dispatch.args_digest.clone());
    approval.sandbox_profile = Some(dispatch.sandbox_profile.clone());
    approval.scope = Some(ApprovalScope::AllowOnce);
    commit
        .event
        .metadata
        .insert("call_id".into(), json!(dispatch.call_id.clone()));
    commit.event.data = Some(RunEventData::ApprovalDecided {
        approval_id: dispatch.approval_id.clone(),
        call_id: dispatch.call_id.clone(),
        decision: ReviewDecision::Approve,
        status: ToolCallStatus::Queued,
    });
    commit.response.run = commit.snapshot.run.clone();
    commit.response.event = commit.event.clone();
    commit.dispatch = Some(dispatch);
    commit
}

fn start_commit(queued: &RunSnapshot) -> DispatchStartCommit {
    let mut snapshot = queued.clone();
    snapshot.run.status = RunStatus::Running;
    snapshot.run.sequence += 1;
    let event = RunEvent {
        sequence: snapshot.run.sequence,
        id: format!("evt-{:06}", snapshot.run.sequence),
        turn: 1,
        step: 5,
        event_type: EventType::ToolCall,
        title: "Local tool dispatch started".into(),
        at: "2026-08-26T01:20:01Z".into(),
        summary: Some("The durable queue claim committed before execution.".into()),
        content: None,
        metadata: BTreeMap::from([("call_id".into(), json!("call-local-001"))]),
        approval: None,
        data: Some(RunEventData::ToolDispatchStarted {
            call_id: "call-local-001".into(),
            executor: "local-dev".into(),
            executor_status: ToolExecutorStatus::Available,
            sandbox_profile: SandboxProfile::WorkspaceWrite,
            status: ToolCallStatus::Running,
        }),
    };
    DispatchStartCommit {
        call_id: "call-local-001".into(),
        expected_sequence: queued.run.sequence,
        snapshot,
        event,
    }
}

fn completion_commit(running: &RunSnapshot) -> DispatchCompleteCommit {
    let mut snapshot = running.clone();
    snapshot.run.status = RunStatus::Succeeded;
    snapshot.run.sequence += 1;
    let outcome = ToolOutcome::Succeeded {
        summary: "Local fixture updated".into(),
        output_digest: Some("sha256:output-local-001".into()),
    };
    let event = RunEvent {
        sequence: snapshot.run.sequence,
        id: format!("evt-{:06}", snapshot.run.sequence),
        turn: 1,
        step: 5,
        event_type: EventType::ToolCall,
        title: "Local tool completed".into(),
        at: "2026-08-26T01:20:02Z".into(),
        summary: Some("The local tool returned a durable result.".into()),
        content: None,
        metadata: BTreeMap::from([("call_id".into(), json!("call-local-001"))]),
        approval: None,
        data: Some(RunEventData::ToolResult {
            call_id: "call-local-001".into(),
            status: outcome.call_status(),
            outcome: outcome.clone(),
        }),
    };
    DispatchCompleteCommit {
        call_id: "call-local-001".into(),
        expected_sequence: running.run.sequence,
        snapshot,
        event,
        result_json: serde_json::to_value(outcome).unwrap(),
    }
}

fn recovery_commit(running: &RunSnapshot) -> DispatchRecoveryCommit {
    let mut snapshot = running.clone();
    snapshot.run.status = RunStatus::NeedsAttention;
    snapshot.run.sequence += 1;
    let outcome = ToolOutcome::OutcomeUnknown {
        summary: "Process stopped after dispatch start; the side effect is unknown.".into(),
    };
    let event = RunEvent {
        sequence: snapshot.run.sequence,
        id: format!("evt-{:06}", snapshot.run.sequence),
        turn: 1,
        step: 5,
        event_type: EventType::ToolCall,
        title: "Tool outcome requires attention".into(),
        at: "2026-08-26T01:21:00Z".into(),
        summary: Some("Started work is never automatically dispatched twice.".into()),
        content: None,
        metadata: BTreeMap::from([("call_id".into(), json!("call-local-001"))]),
        approval: None,
        data: Some(RunEventData::ToolResult {
            call_id: "call-local-001".into(),
            status: outcome.call_status(),
            outcome: outcome.clone(),
        }),
    };
    DispatchRecoveryCommit {
        call_id: "call-local-001".into(),
        expected_sequence: running.run.sequence,
        snapshot,
        event,
        result_json: serde_json::to_value(outcome).unwrap(),
    }
}

fn create_v1_database(path: &Path) {
    let connection = rusqlite::Connection::open(path).unwrap();
    connection
        .pragma_update(None, "foreign_keys", true)
        .unwrap();
    connection
        .execute_batch(
            r#"CREATE TABLE schema_migrations (
                   version INTEGER PRIMARY KEY,
                   applied_at TEXT NOT NULL
               ) STRICT;"#,
        )
        .unwrap();
    connection
        .execute_batch(include_str!("../migrations/0001_init.sql"))
        .unwrap();
    connection
        .execute(
            "INSERT INTO schema_migrations(version, applied_at) VALUES (1, ?1)",
            ["2026-08-26T00:00:00.000Z"],
        )
        .unwrap();

    let (snapshot, events) = seed_fixture();
    connection
        .execute(
            r#"INSERT INTO incidents(
                   id, title, severity, status, service, region, user_impact, since
               ) VALUES (?1, ?2, 'critical', 'mitigating', ?3, ?4, ?5, ?6)"#,
            params![
                snapshot.incident.id,
                snapshot.incident.title,
                snapshot.incident.service,
                snapshot.incident.region,
                snapshot.incident.user_impact,
                snapshot.incident.since,
            ],
        )
        .unwrap();
    connection
        .execute(
            r#"INSERT INTO runs(
                   id, incident_id, status, environment, started_at, duration_seconds, agent,
                   sequence, projection_sequence, metrics_json, evidence_json, tool_policy_json
               ) VALUES (?1, ?2, 'active', ?3, ?4, ?5, ?6, 6, 6, ?7, ?8, ?9)"#,
            params![
                snapshot.run.id,
                snapshot.incident.id,
                snapshot.run.environment,
                snapshot.run.started_at,
                snapshot.run.duration_seconds,
                snapshot.run.agent,
                serde_json::to_string(&snapshot.metrics).unwrap(),
                serde_json::to_string(&snapshot.evidence).unwrap(),
                serde_json::to_string(&snapshot.tool_policy).unwrap(),
            ],
        )
        .unwrap();
    for event in events {
        connection
            .execute(
                r#"INSERT INTO run_events(
                       run_id, sequence, event_id, event_kind, payload_version, payload_json
                   ) VALUES (?1, ?2, ?3, ?4, 1, ?5)"#,
                params![
                    RUN_ID,
                    event.sequence,
                    event.id,
                    event_kind(&event.event_type),
                    serde_json::to_string(&event).unwrap(),
                ],
            )
            .unwrap();
    }
}

fn create_v3_database_with_identity(path: &Path) {
    create_v1_database(path);
    let connection = rusqlite::Connection::open(path).unwrap();
    connection
        .pragma_update(None, "foreign_keys", true)
        .unwrap();
    connection
        .execute_batch(include_str!("../migrations/0002_tool_execution.sql"))
        .unwrap();
    connection
        .execute(
            "INSERT INTO schema_migrations(version, applied_at) VALUES (2, ?1)",
            ["2026-08-26T00:00:01.000Z"],
        )
        .unwrap();
    connection
        .execute_batch(include_str!("../migrations/0003_runtime_identity.sql"))
        .unwrap();
    connection
        .execute(
            "INSERT INTO schema_migrations(version, applied_at) VALUES (3, ?1)",
            ["2026-08-26T00:00:02.000Z"],
        )
        .unwrap();
    connection
        .execute(
            r#"INSERT INTO runtime_identity(
                   singleton, profile, environment, primary_run_id, policy_id,
                   policy_revision, bound_at
               ) VALUES (1, 'production-guarded', 'production', ?1,
                         'production-guarded', 'production-guarded/v1', ?2)"#,
            params![RUN_ID, "2026-08-26T00:00:03.000Z"],
        )
        .unwrap();
}

fn insert_second_run(path: &Path) {
    let connection = rusqlite::Connection::open(path).unwrap();
    connection
        .pragma_update(None, "foreign_keys", true)
        .unwrap();
    connection
        .execute(
            r#"INSERT INTO incidents(
                   id, title, severity, status, service, region, user_impact, since
               ) VALUES ('INC-SECOND', 'Second incident', 'low', 'investigating',
                         'worker', 'local', 'none', '2026-08-26T02:00:00Z')"#,
            [],
        )
        .unwrap();
    connection
        .execute(
            r#"INSERT INTO runs(
                   id, incident_id, status, environment, started_at, duration_seconds,
                   agent, sequence, projection_sequence, metrics_json, evidence_json,
                   tool_policy_json, execution_status
               ) VALUES ('ZR-SECOND', 'INC-SECOND', 'waiting_for_approval', 'production',
                         '2026-08-26T02:00:00Z', 0, 'Zeus Responder', 0, 0,
                         '[]', '[]', NULL, 'waiting_for_approval')"#,
            [],
        )
        .unwrap();
}

fn event_kind(event_type: &EventType) -> &'static str {
    match event_type {
        EventType::System => "system",
        EventType::User => "user",
        EventType::Reasoning => "reasoning",
        EventType::Step => "step",
        EventType::ToolCall => "tool_call",
        EventType::Evidence => "evidence",
        EventType::Approval => "approval",
    }
}

fn insert_raw_event(path: &Path, event_kind: &str, payload_version: i64) {
    let connection = rusqlite::Connection::open(path).unwrap();
    let (_, events) = seed_fixture();
    let mut event = events.last().unwrap().clone();
    event.sequence = 7;
    event.id = "evt-000007".into();
    connection
        .execute(
            r#"INSERT INTO run_events(
                   run_id, sequence, event_id, event_kind, payload_version, payload_json
               ) VALUES (?1, 7, ?2, ?3, ?4, ?5)"#,
            params![
                RUN_ID,
                event.id,
                event_kind,
                payload_version,
                serde_json::to_string(&event).unwrap()
            ],
        )
        .unwrap();
}
