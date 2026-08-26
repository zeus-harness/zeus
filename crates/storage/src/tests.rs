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
    Approval, ApprovalScope, ApprovalStatus, AssistantReplyKind, AssistantReplyProvenance,
    AttachRunRequest, CreateSessionRequest, EventType, EvidenceSummary, FlushSessionRequest,
    IncidentStatus, IncidentSummary, Metric, MetricTone, NotDispatchedReason, ResumeSessionRequest,
    ReviewDecision, ReviewResponse, RunEvent, RunEventData, RunStatus, RunSummary, SandboxProfile,
    SessionEvent, SessionEventData, SessionStatus, SessionTurnStatus, Severity, StartTurnRequest,
    ToolCall, ToolCallStatus, ToolEffect, ToolExecutorStatus, ToolOutcome, ToolPolicySummary,
};
use rusqlite::{OptionalExtension, params};
use serde_json::{Value, json};

use crate::{
    AuthSessionCommit, BootstrapOwnerCommit, ClaimOutcome, CommitOutcome, DispatchCompleteCommit,
    DispatchJobSpec, DispatchRecoveryCommit, DispatchStartCommit, DispatchStatus,
    ReplyClaimOutcome, ReplyFailureCommit, ReplyJobSpec, ReplyJobStatus, ReplyOutcomeUnknownCommit,
    ReplySuccessCommit, ReviewCommit, RunSnapshot, RuntimeIdentity, SqlitePhysicalLimits,
    SqliteStore, StorageError, StorageLimits, StoredUserRole, StoredUserStatus,
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

fn sqlite_main_geometry(path: &Path) -> (u64, u64, u64) {
    let connection = rusqlite::Connection::open(path).unwrap();
    let page_size: u64 = connection
        .pragma_query_value(None, "page_size", |row| row.get::<_, i64>(0))
        .unwrap()
        .try_into()
        .unwrap();
    let page_count: u64 = connection
        .pragma_query_value(None, "page_count", |row| row.get::<_, i64>(0))
        .unwrap()
        .try_into()
        .unwrap();
    let page_bytes = page_size.checked_mul(page_count).unwrap();
    let file_bytes = fs::metadata(path).unwrap().len();
    (page_size, page_count, page_bytes.max(file_bytes))
}

fn admission_exhausted_physical_limits(path: &Path) -> SqlitePhysicalLimits {
    let (page_size, _, main_bytes) = sqlite_main_geometry(path);
    let admission_reserve_bytes = 1024 * 1024;
    SqlitePhysicalLimits {
        max_main_bytes: main_bytes
            .checked_add(admission_reserve_bytes)
            .and_then(|value| value.checked_sub(page_size))
            .unwrap(),
        wal_target_bytes: 64 * 1024,
        min_free_bytes: 1,
        admission_reserve_bytes,
    }
}

fn physical_admission_counts(path: &Path) -> (i64, i64, i64, i64) {
    rusqlite::Connection::open(path)
        .unwrap()
        .query_row(
            r#"SELECT
                   (SELECT COUNT(*) FROM sessions),
                   (SELECT COUNT(*) FROM session_events),
                   (SELECT COUNT(*) FROM session_command_receipts),
                   (SELECT used_bytes FROM event_payload_usage WHERE singleton = 1)"#,
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .unwrap()
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
async fn file_connections_apply_the_exact_physical_pragma_policy() {
    const WAL_HEADER_BYTES: u64 = 32;
    const WAL_FRAME_HEADER_BYTES: u64 = 24;

    let database = TestDatabase::new();
    let physical_limits = SqlitePhysicalLimits {
        max_main_bytes: 64 * 1024 * 1024,
        wal_target_bytes: 1024 * 1024,
        min_free_bytes: 1,
        admission_reserve_bytes: 2 * 1024 * 1024,
    };
    let store = SqliteStore::open_with_limits_and_physical(
        database.path(),
        StorageLimits::default(),
        physical_limits.clone(),
    )
    .await
    .unwrap();
    assert_eq!(store.physical_limits(), &physical_limits);
    store.readiness().await.unwrap();

    let (page_size, _, _) = sqlite_main_geometry(database.path());
    let expected_max_page_count = physical_limits.max_main_bytes / page_size;
    let expected_wal_autocheckpoint = physical_limits
        .wal_target_bytes
        .saturating_sub(WAL_HEADER_BYTES)
        .checked_div(page_size + WAL_FRAME_HEADER_BYTES)
        .unwrap()
        .max(1);
    assert!(expected_wal_autocheckpoint > 0);
    assert_eq!(expected_max_page_count, 16_384);
    assert_eq!(
        store.physical_pragma_snapshot().await.unwrap(),
        (
            expected_max_page_count,
            expected_wal_autocheckpoint,
            physical_limits.wal_target_bytes,
            -2048,
            0,
        )
    );
}

#[tokio::test]
async fn physical_admission_watermark_preserves_reads_and_exact_replay() {
    let database = TestDatabase::new();
    let request = CreateSessionRequest {
        id: "session-physical-replay".into(),
        title: "Physical replay fixture".into(),
    };
    let committed = {
        let store = SqliteStore::open(database.path()).await.unwrap();
        store
            .create_session(request.clone(), "create-physical-replay")
            .await
            .unwrap()
    };
    assert!(!committed.replayed);

    let physical_limits = admission_exhausted_physical_limits(database.path());
    let store = SqliteStore::open_with_limits_and_physical(
        database.path(),
        StorageLimits::default(),
        physical_limits,
    )
    .await
    .unwrap();
    let loaded = store.get_session(&request.id).await.unwrap();
    assert_eq!(loaded.session, committed.session);
    assert!(matches!(
        store.readiness().await,
        Err(StorageError::PhysicalStorageExhausted)
    ));

    let replayed = store
        .create_session(request.clone(), "create-physical-replay")
        .await
        .unwrap();
    assert!(replayed.replayed);
    assert_eq!(replayed.session, committed.session);

    let before = physical_admission_counts(database.path());
    assert!(matches!(
        store
            .create_session(
                CreateSessionRequest {
                    id: "session-physical-rejected".into(),
                    title: "Must not cross the admission watermark".into(),
                },
                "create-physical-rejected",
            )
            .await,
        Err(StorageError::PhysicalStorageExhausted)
    ));
    assert_eq!(physical_admission_counts(database.path()), before);
    assert!(matches!(
        store.get_session("session-physical-rejected").await,
        Err(StorageError::SessionNotFound(_))
    ));
}

#[tokio::test]
async fn reserved_reply_progress_and_finalization_survive_admission_exhaustion() {
    let database = TestDatabase::new();
    {
        let store = created_owned_file_session_store(database.path()).await;
        store
            .start_turn_and_enqueue_reply_for_actor(
                "user-owner",
                "session-alpha",
                StartTurnRequest {
                    turn_id: "turn-physical-finalization".into(),
                    user_message: "This accepted reply must remain settleable".into(),
                    expected_sequence: 1,
                },
                "start-physical-finalization",
                reply_job_spec("reply-physical-finalization", "turn-physical-finalization"),
            )
            .await
            .unwrap();
    }

    let physical_limits = admission_exhausted_physical_limits(database.path());
    let (_, _, main_bytes) = sqlite_main_geometry(database.path());
    assert!(
        main_bytes > physical_limits.max_main_bytes - physical_limits.admission_reserve_bytes,
        "fixture must be below the ordinary admission watermark"
    );
    assert!(
        fs2::available_space(database.path().parent().unwrap()).unwrap()
            >= physical_limits.min_free_bytes,
        "fixture must retain the minimum free space required for accepted work"
    );
    let store = SqliteStore::open_with_limits_and_physical(
        database.path(),
        StorageLimits::default(),
        physical_limits,
    )
    .await
    .unwrap();
    assert!(matches!(
        store.readiness().await,
        Err(StorageError::PhysicalStorageExhausted)
    ));
    assert!(matches!(
        store.claim_next_reply().await.unwrap(),
        ReplyClaimOutcome::Claimed(_)
    ));
    let completed = store
        .complete_reply_failure(ReplyFailureCommit {
            job_id: "reply-physical-finalization".into(),
            expected_sequence: 2,
            error_json: json!({
                "code": "physical_finalization_fixture",
                "message": "settled inside reserved physical headroom",
            }),
        })
        .await
        .unwrap();
    assert!(!completed.replayed);
    assert!(matches!(
        completed.events[0].data,
        SessionEventData::TurnInterrupted { .. }
    ));
    let detail = store.get_session("session-alpha").await.unwrap();
    assert_eq!(detail.session.status, SessionStatus::NeedsAttention);
    assert_eq!(detail.turns[0].status, SessionTurnStatus::Interrupted);
    assert_eq!(
        session_finalization_capacity(
            database.path(),
            "session-alpha",
            "turn-physical-finalization"
        ),
        None
    );
}

#[tokio::test]
async fn physical_main_file_exact_boundary_opens_and_below_boundary_fails() {
    let database = TestDatabase::new();
    {
        let store = SqliteStore::open(database.path()).await.unwrap();
        store
            .create_session(
                CreateSessionRequest {
                    id: "session-main-boundary".into(),
                    title: "Main file boundary".into(),
                },
                "create-main-boundary",
            )
            .await
            .unwrap();
    }
    let (page_size, _, main_bytes) = sqlite_main_geometry(database.path());
    let exact_limits = SqlitePhysicalLimits {
        max_main_bytes: main_bytes,
        wal_target_bytes: page_size,
        min_free_bytes: 1,
        admission_reserve_bytes: page_size * 2,
    };
    let exact = SqliteStore::open_with_limits_and_physical(
        database.path(),
        StorageLimits::default(),
        exact_limits,
    )
    .await
    .unwrap();
    assert_eq!(
        exact
            .get_session("session-main-boundary")
            .await
            .unwrap()
            .session
            .id,
        "session-main-boundary"
    );
    drop(exact);

    let below_limits = SqlitePhysicalLimits {
        max_main_bytes: main_bytes - page_size,
        wal_target_bytes: page_size,
        min_free_bytes: 1,
        admission_reserve_bytes: page_size * 2,
    };
    assert!(matches!(
        SqliteStore::open_with_limits_and_physical(
            database.path(),
            StorageLimits::default(),
            below_limits,
        )
        .await,
        Err(StorageError::PhysicalStorageExhausted)
    ));

    let over_hard = SqlitePhysicalLimits {
        max_main_bytes: SqlitePhysicalLimits::HARD_CEILINGS.max_main_bytes + 1,
        ..SqlitePhysicalLimits::default()
    };
    assert!(matches!(
        SqliteStore::open_with_limits_and_physical(
            database.path(),
            StorageLimits::default(),
            over_hard,
        )
        .await,
        Err(StorageError::InvalidPhysicalLimits(_))
    ));
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
    bootstrap_test_owner(&mismatched).await;
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
async fn point_contexts_match_full_ledger_and_mask_foreign_actors() {
    let store = SqliteStore::open(":memory:").await.unwrap();
    let (snapshot, events) = point_context_fixture();
    store
        .seed_if_empty(snapshot.clone(), events.clone())
        .await
        .unwrap();
    bootstrap_test_owner(&store).await;

    let full = store.load_run(RUN_ID).await.unwrap();
    let review = store
        .review_context_for_actor("user-owner", RUN_ID, "APR-901")
        .await
        .unwrap();
    assert_eq!(review.snapshot, full.snapshot);
    assert_eq!(review.approval, events[5].approval);
    assert_eq!(review.approval_event_sequence, Some(6));
    assert_eq!(review.requested_call, Some(dispatch_fixture_call()));
    assert_eq!(review.requested_call_event_sequence, Some(4));
    assert!(matches!(
        store
            .review_context_for_actor("foreign-user", RUN_ID, "missing-approval")
            .await,
        Err(StorageError::RunNotFound(id)) if id == RUN_ID
    ));

    let commit = approved_dispatch_commit(&snapshot, "point-context-review");
    store
        .commit_review_for_actor("user-owner", commit.clone())
        .await
        .unwrap();
    let settled_review = store
        .review_context_for_actor("user-owner", RUN_ID, "APR-901")
        .await
        .unwrap();
    assert!(settled_review.approval.is_none());
    assert!(settled_review.requested_call.is_none());
    let job = store.dispatch_job("call-local-001").await.unwrap().unwrap();
    let dispatch = store.dispatch_context(&job).await.unwrap();
    let full = store.load_run(RUN_ID).await.unwrap();
    assert_eq!(dispatch.snapshot, full.snapshot);
    assert_eq!(dispatch.approval_event, commit.event);
    assert_eq!(dispatch.requested_call, Some(dispatch_fixture_call()));
    assert_eq!(dispatch.requested_call_event_sequence, Some(4));

    store
        .create_session_for_actor(
            "user-owner",
            CreateSessionRequest {
                id: "session-ZR-1842".into(),
                title: "Checkout API latency".into(),
            },
            "point-context-session",
        )
        .await
        .unwrap();
    store
        .attach_run_for_actor(
            "user-owner",
            "session-ZR-1842",
            AttachRunRequest {
                run_id: RUN_ID.into(),
                expected_sequence: 1,
            },
            "point-context-attach",
        )
        .await
        .unwrap();
    let detail = store.get_session("session-ZR-1842").await.unwrap();
    assert_eq!(
        store.session_summary("session-ZR-1842").await.unwrap(),
        detail.session
    );
    assert!(
        store
            .session_has_run("session-ZR-1842", RUN_ID)
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn point_contexts_fail_closed_on_duplicate_or_mismatched_lookup_rows() {
    let duplicate_database = TestDatabase::new();
    let duplicate_store = SqliteStore::open(duplicate_database.path()).await.unwrap();
    let (snapshot, events) = point_context_fixture();
    duplicate_store
        .seed_if_empty(snapshot.clone(), events.clone())
        .await
        .unwrap();
    bootstrap_test_owner(&duplicate_store).await;
    let mut duplicate = event(3, EventType::ToolCall, "Duplicate requested call");
    duplicate.data = Some(RunEventData::ToolCallRequested {
        call: dispatch_fixture_call(),
        status: ToolCallStatus::Requested,
    });
    replace_run_event_for_test(
        duplicate_database.path(),
        RUN_ID,
        3,
        &duplicate,
        Some("tool_call_requested"),
        Some("call-local-001"),
        None,
        None,
        None,
    );
    assert!(matches!(
        duplicate_store
            .review_context_for_actor("foreign-user", RUN_ID, "APR-901")
            .await,
        Err(StorageError::RunNotFound(id)) if id == RUN_ID
    ));
    assert!(matches!(
        duplicate_store
            .review_context_for_actor("user-owner", RUN_ID, "APR-901")
            .await,
        Err(StorageError::CorruptData(message))
            if message.contains("multiple request events")
    ));

    let mismatch_database = TestDatabase::new();
    let mismatch_store = SqliteStore::open(mismatch_database.path()).await.unwrap();
    mismatch_store
        .seed_if_empty(snapshot, events)
        .await
        .unwrap();
    let mut mismatched = event(4, EventType::ToolCall, "Mismatched requested call");
    let mut call = dispatch_fixture_call();
    call.call_id = "payload-call-does-not-match-projection".into();
    mismatched.data = Some(RunEventData::ToolCallRequested {
        call,
        status: ToolCallStatus::Requested,
    });
    replace_run_event_for_test(
        mismatch_database.path(),
        RUN_ID,
        4,
        &mismatched,
        Some("tool_call_requested"),
        Some("call-local-001"),
        None,
        None,
        None,
    );
    assert!(matches!(
        mismatch_store.review_context(RUN_ID, "APR-901").await,
        Err(StorageError::CorruptData(message))
            if message.contains("lookup projection disagrees")
    ));
}

#[tokio::test]
async fn approval_point_lookup_rejects_duplicate_pending_and_terminal_reuse() {
    let duplicate_pending_database = TestDatabase::new();
    let duplicate_pending_store = SqliteStore::open(duplicate_pending_database.path())
        .await
        .unwrap();
    let (snapshot, events) = point_context_fixture();
    duplicate_pending_store
        .seed_if_empty(snapshot.clone(), events.clone())
        .await
        .unwrap();
    let mut duplicate_pending = event(3, EventType::Approval, "Duplicate pending approval");
    duplicate_pending.approval = events[5].approval.clone();
    duplicate_pending.data = events[5].data.clone();
    replace_run_event_for_test(
        duplicate_pending_database.path(),
        RUN_ID,
        3,
        &duplicate_pending,
        Some("approval_requested"),
        Some("call-local-001"),
        Some("APR-901"),
        Some("pending"),
        Some("rev-2026-08-26"),
    );
    assert!(matches!(
        duplicate_pending_store
            .review_context(RUN_ID, "APR-901")
            .await,
        Err(StorageError::CorruptData(message))
            if message.contains("multiple pending request events")
    ));

    let terminal_reuse_database = TestDatabase::new();
    let terminal_reuse_store = SqliteStore::open(terminal_reuse_database.path())
        .await
        .unwrap();
    terminal_reuse_store
        .seed_if_empty(snapshot, events)
        .await
        .unwrap();
    for sequence in [2_i64, 3_i64] {
        let mut terminal = event(
            sequence as u64,
            EventType::Approval,
            "Reused terminal approval",
        );
        terminal.approval = Some(Approval {
            id: "APR-901".into(),
            status: ApprovalStatus::Approved,
            action: "duplicate terminal".into(),
            tool: "local.echo".into(),
            change: "must fail closed".into(),
            requires_approval: true,
            call_id: Some("call-local-001".into()),
            policy_revision: Some("rev-2026-08-26".into()),
            arguments_digest: Some("sha256:args-local-001".into()),
            sandbox_profile: Some(SandboxProfile::WorkspaceWrite),
            scope: Some(ApprovalScope::AllowOnce),
        });
        terminal.data = Some(RunEventData::ApprovalDecided {
            approval_id: "APR-901".into(),
            call_id: "call-local-001".into(),
            decision: ReviewDecision::Approve,
            status: ToolCallStatus::Queued,
        });
        replace_run_event_for_test(
            terminal_reuse_database.path(),
            RUN_ID,
            sequence,
            &terminal,
            Some("approval_decided"),
            Some("call-local-001"),
            Some("APR-901"),
            Some("approved"),
            Some("rev-2026-08-26"),
        );
    }
    assert!(matches!(
        terminal_reuse_store
            .review_context(RUN_ID, "APR-901")
            .await,
        Err(StorageError::CorruptData(message))
            if message.contains("reused by more than one request/decision pair")
    ));
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

#[tokio::test]
async fn review_note_envelope_rejects_before_receipt_or_ledger_side_effects() {
    let database = TestDatabase::new();
    let store = seeded_file_store(database.path()).await;
    bootstrap_test_owner(&store).await;
    let (snapshot, _) = seed_fixture();

    let oversized_note = "🙂".repeat(protocol::REVIEW_NOTE_MAX_BYTES / 4 + 1);
    let mut oversized = approved_commit(&snapshot, "oversized-review-note");
    oversized.event.content = Some(oversized_note.clone());
    oversized.response.event = oversized.event.clone();
    oversized.request_fingerprint = serde_json::to_string(&json!({
        "approval_id": "APR-901",
        "decision": "approve",
        "note": oversized_note,
        "run_id": RUN_ID,
    }))
    .unwrap();
    assert!(matches!(
        store.commit_review_for_actor("user-owner", oversized).await,
        Err(StorageError::InvalidResourceEnvelope(_))
    ));
    assert!(
        store
            .review_receipt_for_actor("user-owner", RUN_ID, "oversized-review-note")
            .await
            .unwrap()
            .is_none()
    );
    let unchanged = store.load_run(RUN_ID).await.unwrap();
    assert_eq!(unchanged.snapshot.run.sequence, snapshot.run.sequence);
    assert_eq!(unchanged.events.len(), 6);

    let boundary_note = "🙂".repeat(protocol::REVIEW_NOTE_MAX_BYTES / 4);
    let mut boundary = approved_commit(&snapshot, "boundary-review-note");
    boundary.event.content = Some(boundary_note.clone());
    boundary.response.event = boundary.event.clone();
    boundary.request_fingerprint = serde_json::to_string(&json!({
        "approval_id": "APR-901",
        "decision": "approve",
        "note": boundary_note,
        "run_id": RUN_ID,
    }))
    .unwrap();
    assert_eq!(
        store
            .commit_review_for_actor("user-owner", boundary)
            .await
            .unwrap(),
        CommitOutcome::Committed
    );
}

#[tokio::test]
async fn legacy_oversized_run_and_review_identifiers_remain_usable_after_reopen() {
    let database = TestDatabase::new();
    let long_run_id = "r".repeat(protocol::RESOURCE_ID_MAX_BYTES + 1);
    let long_event_id = "e".repeat(protocol::RESOURCE_ID_MAX_BYTES + 1);
    let long_approval_id = "a".repeat(protocol::RESOURCE_ID_MAX_BYTES + 1);
    let (mut snapshot, events) = seed_fixture();
    snapshot.run.id.clone_from(&long_run_id);

    {
        let store = SqliteStore::open(database.path()).await.unwrap();
        assert!(store.seed_if_empty(snapshot.clone(), events).await.unwrap());
        bootstrap_test_owner(&store).await;
    }

    let reopened = SqliteStore::open(database.path()).await.unwrap();
    assert_eq!(
        reopened
            .load_run_for_actor("user-owner", &long_run_id)
            .await
            .unwrap()
            .snapshot
            .run
            .id,
        long_run_id
    );
    assert_eq!(
        reopened
            .events_after_for_actor("user-owner", &long_run_id, 0)
            .await
            .unwrap()
            .len(),
        6
    );
    let legacy_page = reopened
        .run_event_page_for_actor("user-owner", &long_run_id, 0, 3)
        .await
        .unwrap();
    assert_eq!(legacy_page.items.len(), 3);
    assert_eq!(legacy_page.next_after, Some(3));
    assert_eq!(legacy_page.head_sequence, 6);
    assert!(legacy_page.has_more);

    let mut commit = approved_commit(&snapshot, "legacy-long-run-review");
    commit.event.id.clone_from(&long_event_id);
    commit.event.approval.as_mut().unwrap().id = long_approval_id.clone();
    commit.response.event = commit.event.clone();
    commit.request_fingerprint = serde_json::to_string(&json!({
        "approval_id": long_approval_id,
        "decision": "approve",
        "note": "ship it",
        "run_id": long_run_id,
    }))
    .unwrap();
    assert_eq!(
        reopened
            .commit_review_for_actor("user-owner", commit.clone())
            .await
            .unwrap(),
        CommitOutcome::Committed
    );
    let receipt = reopened
        .review_receipt_for_actor(
            "user-owner",
            &commit.snapshot.run.id,
            "legacy-long-run-review",
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(receipt.response.event.id, long_event_id);

    let legacy_note = "n".repeat(protocol::REVIEW_NOTE_MAX_BYTES + 1);
    let legacy_fingerprint = serde_json::to_string(&json!({
        "approval_id": "legacy-approval",
        "decision": "approve",
        "note": legacy_note,
        "run_id": &commit.snapshot.run.id,
    }))
    .unwrap();
    let connection = rusqlite::Connection::open(database.path()).unwrap();
    connection
        .pragma_update(None, "foreign_keys", true)
        .unwrap();
    connection
        .execute(
            r#"INSERT INTO idempotency_receipts(
                   actor_scope, idempotency_key, operation, request_fingerprint,
                   response_json, run_id, event_sequence, created_at
               ) VALUES (
                   'user-owner', 'legacy-long-note-receipt', 'review', ?1,
                   ?2, ?3, 7, '2026-08-27T00:00:00.000Z'
               )"#,
            params![
                legacy_fingerprint,
                serde_json::to_string(&commit.response).unwrap(),
                &commit.snapshot.run.id,
            ],
        )
        .unwrap();
    drop(connection);
    assert!(
        reopened
            .review_receipt_for_actor(
                "user-owner",
                &commit.snapshot.run.id,
                "legacy-long-note-receipt",
            )
            .await
            .unwrap()
            .is_some(),
        "legacy oversized review fingerprints must remain decodable"
    );
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
    bootstrap_test_owner(&store).await;
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
    assert_eq!(versions, vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]);
    let owner: Option<String> = connection
        .query_row(
            "SELECT owner_user_id FROM runs WHERE id = ?1",
            [RUN_ID],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        owner, None,
        "legacy state is claimed only during owner bootstrap"
    );
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
async fn v8_point_fixture_migrates_without_rewriting_oversized_durable_ids() {
    let database = TestDatabase::new();
    let long_run_id = format!("v8-run-{}", "r".repeat(protocol::RESOURCE_ID_MAX_BYTES + 1));
    let pending_call_id = format!(
        "v8-pending-call-{}",
        "c".repeat(protocol::RESOURCE_ID_MAX_BYTES + 1)
    );
    let pending_approval_id = format!(
        "v8-pending-approval-{}",
        "a".repeat(protocol::RESOURCE_ID_MAX_BYTES + 1)
    );
    let dispatch_call_id = format!(
        "v8-dispatch-call-{}",
        "d".repeat(protocol::RESOURCE_ID_MAX_BYTES + 1)
    );
    let dispatch_approval_id = format!(
        "v8-dispatch-approval-{}",
        "p".repeat(protocol::RESOURCE_ID_MAX_BYTES + 1)
    );
    create_v8_database_with_oversized_point_fixture(
        database.path(),
        &long_run_id,
        &pending_call_id,
        &pending_approval_id,
        &dispatch_call_id,
        &dispatch_approval_id,
    );
    let payloads_before = run_event_payloads(database.path(), &long_run_id);

    let store = SqliteStore::open(database.path()).await.unwrap();
    store.readiness().await.unwrap();
    let review = store
        .review_context(&long_run_id, &pending_approval_id)
        .await
        .unwrap();
    assert_eq!(
        review
            .approval
            .as_ref()
            .map(|approval| approval.id.as_str()),
        Some(pending_approval_id.as_str())
    );
    assert_eq!(
        review
            .requested_call
            .as_ref()
            .map(|call| call.call_id.as_str()),
        Some(pending_call_id.as_str())
    );
    let job = store
        .dispatch_job(&dispatch_call_id)
        .await
        .unwrap()
        .unwrap();
    let dispatch = store.dispatch_context(&job).await.unwrap();
    assert_eq!(dispatch.approval_event.sequence, 4);
    assert_eq!(
        dispatch
            .approval_event
            .approval
            .as_ref()
            .map(|approval| approval.id.as_str()),
        Some(dispatch_approval_id.as_str())
    );
    assert_eq!(
        dispatch
            .requested_call
            .as_ref()
            .map(|call| call.call_id.as_str()),
        Some(dispatch_call_id.as_str())
    );
    drop(store);

    assert_eq!(
        run_event_payloads(database.path(), &long_run_id),
        payloads_before,
        "v9-v11 migrations must not rewrite immutable event payloads"
    );
    let connection = rusqlite::Connection::open(database.path()).unwrap();
    let version: i64 = connection
        .query_row("SELECT MAX(version) FROM schema_migrations", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(version, 11);
    let approval_plan = explain_query_plan(
        &connection,
        r#"SELECT sequence FROM run_events
           WHERE run_id = ?1 AND approval_id = ?2
           ORDER BY sequence DESC LIMIT 3"#,
        params![long_run_id, pending_approval_id],
    );
    assert!(approval_plan.contains("run_events_approval_lookup_idx"));
    let call_plan = explain_query_plan(
        &connection,
        r#"SELECT sequence FROM run_events
           WHERE run_id = ?1 AND data_kind = 'tool_call_requested' AND call_id = ?2
           ORDER BY sequence LIMIT 2"#,
        params![long_run_id, dispatch_call_id],
    );
    assert!(call_plan.contains("run_events_tool_call_lookup_idx"));
    let keyset_plan = explain_query_plan(
        &connection,
        r#"SELECT run_id, sequence FROM run_events
           WHERE (run_id, sequence) > (?1, ?2)
           ORDER BY run_id, sequence LIMIT 128"#,
        params!["", 0_i64],
    );
    assert!(
        keyset_plan.contains("SEARCH run_events USING PRIMARY KEY"),
        "unexpected migration keyset plan: {keyset_plan}"
    );
}

#[tokio::test]
async fn v8_gap_aborts_v9_migration_and_restores_the_append_only_schema() {
    let database = TestDatabase::new();
    create_v8_database_with_legacy_dispatch(database.path());
    let connection = rusqlite::Connection::open(database.path()).unwrap();
    connection
        .execute_batch("DROP TRIGGER run_events_reject_delete;")
        .unwrap();
    assert_eq!(
        connection
            .execute(
                "DELETE FROM run_events WHERE run_id = ?1 AND sequence = 3",
                [RUN_ID],
            )
            .unwrap(),
        1
    );
    connection
        .execute_batch(
            r#"CREATE TRIGGER run_events_reject_delete
               BEFORE DELETE ON run_events
               BEGIN
                   SELECT RAISE(ABORT, 'run_events are append-only');
               END;"#,
        )
        .unwrap();
    drop(connection);

    let error = match SqliteStore::open(database.path()).await {
        Ok(_) => panic!("a gapped v8 ledger must not migrate"),
        Err(error) => error,
    };
    assert!(matches!(
        error,
        StorageError::CorruptData(message) if message.contains("ledger is not contiguous")
    ));

    let connection = rusqlite::Connection::open(database.path()).unwrap();
    let version: i64 = connection
        .query_row("SELECT MAX(version) FROM schema_migrations", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(version, 8);
    let lookup_columns: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM pragma_table_info('run_events') WHERE name = 'data_kind'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(lookup_columns, 0, "ALTER TABLE must roll back with v9");
    let update_trigger: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM sqlite_schema WHERE type = 'trigger' AND name = 'run_events_reject_update'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(update_trigger, 1, "the dropped trigger must be restored");
    assert!(
        connection
            .execute(
                "UPDATE run_events SET event_id = event_id WHERE run_id = ?1 AND sequence = 1",
                [RUN_ID],
            )
            .is_err()
    );
}

#[tokio::test]
async fn v7_legacy_dispatch_is_rejected_before_bootstrap_then_claimed_as_history() {
    let database = TestDatabase::new();
    create_v7_database_with_legacy_dispatch(database.path());

    let store = SqliteStore::open(database.path()).await.unwrap();
    store.readiness().await.unwrap();
    let migrated = store.dispatch_job("call-v7-legacy").await.unwrap().unwrap();
    assert_eq!(migrated.approving_actor_user_id, None);
    let (snapshot, _) = seed_fixture();
    let mut queued = snapshot;
    queued.run.status = RunStatus::Queued;
    let mut start = start_commit(&queued);
    start.call_id = "call-v7-legacy".into();
    start
        .event
        .metadata
        .insert("call_id".into(), json!("call-v7-legacy"));
    if let Some(RunEventData::ToolDispatchStarted { call_id, .. }) = &mut start.event.data {
        *call_id = "call-v7-legacy".into();
    }
    let outcome = store.claim_next_dispatch(start).await.unwrap();
    let ClaimOutcome::Rejected(rejection) = outcome else {
        panic!("a migrated dispatch without an actor must fail closed");
    };
    assert_eq!(rejection.job.status, DispatchStatus::Rejected);
    assert_eq!(rejection.job.approving_actor_user_id, None);

    bootstrap_test_owner(&store).await;
    let claimed_history = store.dispatch_job("call-v7-legacy").await.unwrap().unwrap();
    assert_eq!(
        claimed_history.approving_actor_user_id.as_deref(),
        Some("user-owner")
    );
    assert_eq!(claimed_history.status, DispatchStatus::Rejected);
}

#[tokio::test]
async fn owner_bootstrap_claims_legacy_state_and_auth_sessions_are_revocable() {
    let database = TestDatabase::new();
    let store = seeded_file_store(database.path()).await;
    store
        .seed_demo_session("session-ZR-1842", "Checkout API latency", RUN_ID)
        .await
        .unwrap();
    assert!(!store.has_users().await.unwrap());

    let bootstrap_hash = "a".repeat(64);
    let session_hash = "b".repeat(64);
    let csrf_hash = "c".repeat(64);
    let expiry = (chrono::Utc::now() + chrono::Duration::hours(1))
        .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    store
        .replace_bootstrap_token(&bootstrap_hash, &expiry)
        .await
        .unwrap();
    let (owner, preferences) = store
        .bootstrap_owner(BootstrapOwnerCommit {
            bootstrap_token_hash: bootstrap_hash.clone(),
            user_id: "user-owner".into(),
            username: "owner".into(),
            password_hash: "$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$ZGlnaWVzdA".into(),
            session_token_hash: session_hash.clone(),
            csrf_hash: csrf_hash.clone(),
            session_expires_at: expiry.clone(),
        })
        .await
        .unwrap();

    assert_eq!(owner.role, StoredUserRole::Owner);
    assert_eq!(owner.status, StoredUserStatus::Active);
    assert_eq!(preferences.theme, "system");
    assert_eq!(preferences.revision, 1);
    assert!(store.has_users().await.unwrap());

    let credential = store
        .credential_for_username("OWNER")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(credential.user.id, owner.id);
    assert!(credential.password_hash.starts_with("$argon2id$"));
    let principal = store.authenticate(&session_hash).await.unwrap().unwrap();
    assert_eq!(principal.user, owner);
    assert_eq!(principal.csrf_hash, csrf_hash);

    let updated = store
        .update_preferences("user-owner", 1, "dark", Some("local-fallback"))
        .await
        .unwrap();
    assert_eq!(updated.theme, "dark");
    assert_eq!(updated.revision, 2);
    assert!(matches!(
        store
            .update_preferences("user-owner", 1, "light", None)
            .await,
        Err(StorageError::ConcurrentModification)
    ));

    let connection = rusqlite::Connection::open(database.path()).unwrap();
    let run_owner: String = connection
        .query_row(
            "SELECT owner_user_id FROM runs WHERE id = ?1",
            [RUN_ID],
            |row| row.get(0),
        )
        .unwrap();
    let session_owner: String = connection
        .query_row(
            "SELECT owner_user_id FROM sessions WHERE id = 'session-ZR-1842'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(run_owner, "user-owner");
    assert_eq!(session_owner, "user-owner");

    assert!(store.revoke_auth_session(&session_hash).await.unwrap());
    assert!(store.authenticate(&session_hash).await.unwrap().is_none());
    assert!(matches!(
        store
            .replace_bootstrap_token(&"d".repeat(64), &expiry)
            .await,
        Err(StorageError::AccountAlreadyConfigured)
    ));
    assert!(matches!(
        store
            .bootstrap_owner(BootstrapOwnerCommit {
                bootstrap_token_hash: bootstrap_hash,
                user_id: "other-owner".into(),
                username: "other".into(),
                password_hash: "$argon2id$unused".into(),
                session_token_hash: "e".repeat(64),
                csrf_hash: "f".repeat(64),
                session_expires_at: expiry,
            })
            .await,
        Err(StorageError::AccountAlreadyConfigured)
    ));
}

#[tokio::test]
async fn auth_session_creation_rejects_unknown_users() {
    let store = SqliteStore::open(":memory:").await.unwrap();
    let expiry = (chrono::Utc::now() + chrono::Duration::hours(1))
        .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    assert!(matches!(
        store
            .create_auth_session(AuthSessionCommit {
                user_id: "missing-user".into(),
                session_token_hash: "a".repeat(64),
                csrf_hash: "b".repeat(64),
                expires_at: expiry,
            })
            .await,
        Err(StorageError::UserNotFound(id)) if id == "missing-user"
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
async fn resource_envelope_rejects_noncanonical_keys_without_receipts_or_sessions() {
    let database = TestDatabase::new();
    let store = SqliteStore::open(database.path()).await.unwrap();
    let invalid_keys = [
        "".to_owned(),
        " leading".to_owned(),
        "trailing ".to_owned(),
        "two words".to_owned(),
        "line\nbreak".to_owned(),
        "clé".to_owned(),
        "x".repeat(protocol::IDEMPOTENCY_KEY_MAX_BYTES + 1),
    ];

    for (index, key) in invalid_keys.iter().enumerate() {
        let result = store
            .create_session(
                CreateSessionRequest {
                    id: format!("session-invalid-key-{index}"),
                    title: "Must not be persisted".into(),
                },
                key,
            )
            .await;
        if key.is_empty() {
            assert!(matches!(result, Err(StorageError::EmptyIdempotencyKey)));
        } else {
            assert!(matches!(
                result,
                Err(StorageError::InvalidResourceEnvelope(_))
            ));
        }
    }

    assert!(store.list_sessions().await.unwrap().is_empty());
    let connection = rusqlite::Connection::open(database.path()).unwrap();
    let receipts: i64 = connection
        .query_row("SELECT COUNT(*) FROM session_command_receipts", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(receipts, 0);

    let max_key = "k".repeat(protocol::IDEMPOTENCY_KEY_MAX_BYTES);
    store
        .create_session(
            CreateSessionRequest {
                id: "session-max-key".into(),
                title: "Exact key boundary".into(),
            },
            &max_key,
        )
        .await
        .unwrap();
}

#[tokio::test]
async fn create_envelope_is_validated_before_fingerprint_and_receipt_lookup() {
    let database = TestDatabase::new();
    let store = SqliteStore::open(database.path()).await.unwrap();
    store
        .create_session(
            CreateSessionRequest {
                id: "session-existing".into(),
                title: "Existing receipt".into(),
            },
            "shared-create-envelope",
        )
        .await
        .unwrap();

    let oversized_title = "🙂".repeat(protocol::SESSION_TITLE_MAX_BYTES / 4 + 1);
    assert!(matches!(
        store
            .create_session(
                CreateSessionRequest {
                    id: "session-oversized-title".into(),
                    title: oversized_title,
                },
                "shared-create-envelope",
            )
            .await,
        Err(StorageError::InvalidResourceEnvelope(_))
    ));
    assert!(matches!(
        store.get_session("session-oversized-title").await,
        Err(StorageError::SessionNotFound(_))
    ));

    store
        .create_session(
            CreateSessionRequest {
                id: "session-max-title".into(),
                title: "🙂".repeat(protocol::SESSION_TITLE_MAX_BYTES / 4),
            },
            "max-title-envelope",
        )
        .await
        .unwrap();
    let max_session_id = "s".repeat(protocol::SESSION_ID_MAX_BYTES);
    let created_at_max_id = store
        .create_session(
            CreateSessionRequest {
                id: max_session_id.clone(),
                title: "Exact session ID boundary".into(),
            },
            "max-session-id-envelope",
        )
        .await
        .unwrap();
    assert!(created_at_max_id.event.id.len() <= protocol::RESOURCE_ID_MAX_BYTES);
    let started_at_max_id = store
        .start_turn(
            &max_session_id,
            StartTurnRequest {
                turn_id: "t".repeat(protocol::TURN_ID_MAX_BYTES),
                user_message: "Event IDs stay ledger-local".into(),
                expected_sequence: 1,
            },
            "max-session-id-start-envelope",
        )
        .await
        .unwrap();
    assert!(started_at_max_id.event.id.len() <= protocol::RESOURCE_ID_MAX_BYTES);
    assert!(
        store
            .get_session(&max_session_id)
            .await
            .unwrap()
            .events
            .iter()
            .all(|event| event.id.len() <= protocol::RESOURCE_ID_MAX_BYTES)
    );
    assert!(matches!(
        store
            .create_session(
                CreateSessionRequest {
                    id: "s".repeat(protocol::SESSION_ID_MAX_BYTES + 1),
                    title: "Too long".into(),
                },
                "oversized-session-id-envelope",
            )
            .await,
        Err(StorageError::InvalidResourceEnvelope(_))
    ));

    let connection = rusqlite::Connection::open(database.path()).unwrap();
    let shared_receipts: i64 = connection
        .query_row(
            r#"SELECT COUNT(*) FROM session_command_receipts
               WHERE operation = 'create_session'
                 AND idempotency_key = 'shared-create-envelope'"#,
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(shared_receipts, 1);
}

#[tokio::test]
async fn start_turn_envelope_is_validated_before_fingerprint_and_receipt_lookup() {
    let database = TestDatabase::new();
    let store = SqliteStore::open(database.path()).await.unwrap();
    for (id, key) in [
        ("session-envelope-a", "create-envelope-a"),
        ("session-envelope-b", "create-envelope-b"),
        ("session-envelope-c", "create-envelope-c"),
    ] {
        store
            .create_session(
                CreateSessionRequest {
                    id: id.into(),
                    title: format!("Envelope fixture {id}"),
                },
                key,
            )
            .await
            .unwrap();
    }

    store
        .start_turn(
            "session-envelope-a",
            StartTurnRequest {
                turn_id: "turn-envelope-a".into(),
                user_message: "Persist the first receipt".into(),
                expected_sequence: 1,
            },
            "shared-start-envelope",
        )
        .await
        .unwrap();

    let oversized_message = "🙂".repeat(protocol::USER_MESSAGE_MAX_BYTES / 4 + 1);
    assert!(matches!(
        store
            .start_turn(
                "session-envelope-b",
                StartTurnRequest {
                    turn_id: "turn-envelope-b".into(),
                    user_message: oversized_message,
                    expected_sequence: 1,
                },
                "shared-start-envelope",
            )
            .await,
        Err(StorageError::InvalidResourceEnvelope(_))
    ));

    let untouched = store.get_session("session-envelope-b").await.unwrap();
    assert_eq!(untouched.session.sequence, 1);
    assert!(untouched.turns.is_empty());
    assert_eq!(untouched.events.len(), 1);

    store
        .start_turn(
            "session-envelope-c",
            StartTurnRequest {
                turn_id: "🙂".repeat(protocol::TURN_ID_MAX_BYTES / 4),
                user_message: "🙂".repeat(protocol::USER_MESSAGE_MAX_BYTES / 4),
                expected_sequence: 1,
            },
            "max-start-envelope",
        )
        .await
        .unwrap();

    assert!(matches!(
        store
            .start_turn(
                "session-envelope-b",
                StartTurnRequest {
                    turn_id: "🙂".repeat(protocol::TURN_ID_MAX_BYTES / 4 + 1),
                    user_message: "Must remain side-effect free".into(),
                    expected_sequence: 1,
                },
                "oversized-turn-id-envelope",
            )
            .await,
        Err(StorageError::InvalidResourceEnvelope(_))
    ));
    let still_untouched = store.get_session("session-envelope-b").await.unwrap();
    assert_eq!(still_untouched.session.sequence, 1);
    assert!(still_untouched.turns.is_empty());

    let connection = rusqlite::Connection::open(database.path()).unwrap();
    let shared_receipts: i64 = connection
        .query_row(
            r#"SELECT COUNT(*) FROM session_command_receipts
               WHERE operation = 'start_turn'
                 AND idempotency_key = 'shared-start-envelope'"#,
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(shared_receipts, 1);
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
    assert_eq!(recovered[0].event.sequence, 3);
    assert!(matches!(
        recovered[0].event.data,
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
    assert!(events.iter().all(|recovered| matches!(
        recovered.event.data,
        SessionEventData::TurnInterrupted { .. }
    )));
    assert!(store.recover_open_turns().await.unwrap().is_empty());
    for session_id in ["session-alpha", "session-beta"] {
        let detail = store.get_session(session_id).await.unwrap();
        assert_eq!(detail.session.status, SessionStatus::NeedsAttention);
        assert_eq!(detail.turns[0].status, SessionTurnStatus::Interrupted);
    }
}

#[tokio::test]
async fn open_turn_and_started_reply_recovery_use_fixed_sixty_four_row_batches() {
    const TOTAL: usize = 65;

    let limits = StorageLimits {
        open_turns_per_scope: TOTAL,
        open_turns_global: TOTAL,
        active_reply_jobs_per_scope: TOTAL,
        active_reply_jobs_global: TOTAL,
        ..StorageLimits::default()
    };

    let open_store = SqliteStore::open_with_limits(":memory:", limits.clone())
        .await
        .unwrap();
    for index in 0..TOTAL {
        let session_id = format!("session-open-batch-{index:03}");
        let turn_id = format!("turn-open-batch-{index:03}");
        open_store
            .create_session(
                CreateSessionRequest {
                    id: session_id.clone(),
                    title: format!("Open recovery batch {index}"),
                },
                &format!("create-open-batch-{index:03}"),
            )
            .await
            .unwrap();
        open_store
            .start_turn(
                &session_id,
                StartTurnRequest {
                    turn_id,
                    user_message: "recover this open turn".into(),
                    expected_sequence: 1,
                },
                &format!("start-open-batch-{index:03}"),
            )
            .await
            .unwrap();
    }
    assert_eq!(open_store.recover_open_turns().await.unwrap().len(), 64);
    assert_eq!(open_store.recover_open_turns().await.unwrap().len(), 1);
    assert!(open_store.recover_open_turns().await.unwrap().is_empty());

    let reply_store = SqliteStore::open_with_limits(":memory:", limits)
        .await
        .unwrap();
    bootstrap_test_owner(&reply_store).await;
    for index in 0..TOTAL {
        let session_id = format!("session-reply-batch-{index:03}");
        let turn_id = format!("turn-reply-batch-{index:03}");
        reply_store
            .create_session_for_actor(
                "user-owner",
                CreateSessionRequest {
                    id: session_id.clone(),
                    title: format!("Reply recovery batch {index}"),
                },
                &format!("create-reply-batch-{index:03}"),
            )
            .await
            .unwrap();
        reply_store
            .start_turn_and_enqueue_reply_for_actor(
                "user-owner",
                &session_id,
                StartTurnRequest {
                    turn_id: turn_id.clone(),
                    user_message: "claim this reply".into(),
                    expected_sequence: 1,
                },
                &format!("start-reply-batch-{index:03}"),
                reply_job_spec(&format!("reply-batch-{index:03}"), &turn_id),
            )
            .await
            .unwrap();
    }
    for _ in 0..TOTAL {
        assert!(matches!(
            reply_store.claim_next_reply().await.unwrap(),
            ReplyClaimOutcome::Claimed(_)
        ));
    }
    assert_eq!(
        reply_store.recover_started_replies().await.unwrap().len(),
        64
    );
    assert_eq!(
        reply_store.recover_started_replies().await.unwrap().len(),
        1
    );
    assert!(
        reply_store
            .recover_started_replies()
            .await
            .unwrap()
            .is_empty()
    );
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
async fn reply_start_is_atomic_actor_scoped_and_success_is_idempotent() {
    let database = TestDatabase::new();
    let store = created_owned_file_session_store(database.path()).await;
    let request = StartTurnRequest {
        turn_id: "turn-reply-success".into(),
        user_message: "Summarize the durable evidence".into(),
        expected_sequence: 1,
    };
    let spec = reply_job_spec("reply-success", "turn-reply-success");

    assert!(matches!(
        store
            .start_turn_and_enqueue_reply_with_failure(
                "session-alpha",
                request.clone(),
                "reply-start-atomic",
                spec.clone(),
            )
            .await,
        Err(StorageError::InjectedFailure)
    ));
    assert!(store.reply_job(&spec.id).await.unwrap().is_none());
    let unchanged = store.get_session("session-alpha").await.unwrap();
    assert_eq!(unchanged.session.sequence, 1);
    assert!(unchanged.turns.is_empty());

    let enqueued = store
        .start_turn_and_enqueue_reply(
            "session-alpha",
            request.clone(),
            "reply-start-atomic",
            spec.clone(),
        )
        .await
        .unwrap();
    assert!(!enqueued.start.replayed);
    assert_eq!(enqueued.start.session.sequence, 2);
    assert_eq!(enqueued.job.status, ReplyJobStatus::Queued);
    let replay = store
        .start_turn_and_enqueue_reply("session-alpha", request, "reply-start-atomic", spec.clone())
        .await
        .unwrap();
    assert!(replay.start.replayed);
    assert_eq!(replay.job, enqueued.job);

    let connection = rusqlite::Connection::open(database.path()).unwrap();
    let actor_scope: String = connection
        .query_row(
            r#"SELECT actor_scope FROM session_command_receipts
               WHERE operation = 'start_turn' AND idempotency_key = 'reply-start-atomic'"#,
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(actor_scope, "user-owner");
    drop(connection);

    let ReplyClaimOutcome::Claimed(claimed) = store.claim_next_reply().await.unwrap() else {
        panic!("the queued reply must be claimable");
    };
    assert_eq!(claimed.id, spec.id);
    assert_eq!(claimed.status, ReplyJobStatus::Started);
    let commit = ReplySuccessCommit {
        job_id: spec.id,
        expected_sequence: 2,
        assistant_message: "The evidence is durable and internally consistent.".into(),
        provenance: AssistantReplyProvenance {
            provider_id: "test-provider".into(),
            model: Some("test-model".into()),
            reply_kind: AssistantReplyKind::Model,
        },
        response_json: model_reply_json("The evidence is durable and internally consistent."),
    };
    assert!(matches!(
        store
            .complete_reply_success_with_failure(commit.clone())
            .await,
        Err(StorageError::InjectedFailure)
    ));
    assert_eq!(
        store
            .reply_job(&commit.job_id)
            .await
            .unwrap()
            .unwrap()
            .status,
        ReplyJobStatus::Started
    );
    let open = store.get_session("session-alpha").await.unwrap();
    assert_eq!(open.session.sequence, 2);
    assert_eq!(open.turns[0].status, SessionTurnStatus::Open);

    let completed = store.complete_reply_success(commit.clone()).await.unwrap();
    assert!(!completed.replayed);
    assert_eq!(completed.job.status, ReplyJobStatus::Succeeded);
    assert_eq!(completed.session.status, SessionStatus::Ready);
    assert_eq!(completed.session.sequence, 4);
    assert_eq!(completed.events.len(), 2);
    assert_eq!(
        completed.events[0].data,
        SessionEventData::AssistantMessage {
            turn_id: "turn-reply-success".into(),
            content: "The evidence is durable and internally consistent.".into(),
            provenance: Some(AssistantReplyProvenance {
                provider_id: "test-provider".into(),
                model: Some("test-model".into()),
                reply_kind: AssistantReplyKind::Model,
            }),
        }
    );
    assert!(matches!(
        completed.events[1].data,
        SessionEventData::TurnFlushed { .. }
    ));
    let replay = store.complete_reply_success(commit.clone()).await.unwrap();
    assert!(replay.replayed);
    assert_eq!(replay.events, completed.events);
    let mut conflicting = commit;
    conflicting.response_json["finish_reason"] = json!("length");
    assert!(matches!(
        store.complete_reply_success(conflicting).await,
        Err(StorageError::IdempotencyConflict)
    ));
    assert_eq!(
        store
            .get_session("session-alpha")
            .await
            .unwrap()
            .events
            .len(),
        4
    );
}

#[tokio::test]
async fn actor_scoped_session_creation_sets_owner_required_by_reply_enqueue() {
    let store = SqliteStore::open(":memory:").await.unwrap();
    bootstrap_test_owner(&store).await;
    let request = alpha_session_request();
    let created = store
        .create_session_for_actor("user-owner", request.clone(), "actor-create-session")
        .await
        .unwrap();
    assert!(!created.replayed);
    assert!(
        store
            .create_session_for_actor("user-owner", request, "actor-create-session")
            .await
            .unwrap()
            .replayed
    );
    let enqueued = store
        .start_turn_and_enqueue_reply(
            "session-alpha",
            StartTurnRequest {
                turn_id: "turn-owned".into(),
                user_message: "The actor owns this session".into(),
                expected_sequence: 1,
            },
            "start-owned",
            reply_job_spec("reply-owned", "turn-owned"),
        )
        .await
        .unwrap();
    assert_eq!(enqueued.job.actor_user_id, "user-owner");

    let legacy_request = CreateSessionRequest {
        id: "session-unowned".into(),
        title: "Unowned after bootstrap".into(),
    };
    store
        .create_session(legacy_request, "legacy-create-after-bootstrap")
        .await
        .unwrap();
    assert!(matches!(
        store
            .start_turn_and_enqueue_reply(
                "session-unowned",
                StartTurnRequest {
                    turn_id: "turn-unowned".into(),
                    user_message: "Must fail closed".into(),
                    expected_sequence: 1,
                },
                "start-unowned",
                reply_job_spec("reply-unowned", "turn-unowned"),
            )
            .await,
        Err(StorageError::SessionNotFound(_))
    ));
}

#[tokio::test]
async fn legacy_oversized_session_and_reply_settle_after_file_database_reopen() {
    let database = TestDatabase::new();
    let session_id = "s".repeat(protocol::SESSION_ID_MAX_BYTES + 1);
    let turn_id = "t".repeat(protocol::TURN_ID_MAX_BYTES + 1);
    let user_message = "x".repeat(protocol::USER_MESSAGE_MAX_BYTES + 1);
    let job_id = "reply-legacy-resource-envelope";

    {
        let store = SqliteStore::open(database.path()).await.unwrap();
        bootstrap_test_owner(&store).await;
    }
    insert_legacy_oversized_reply_fixture(
        database.path(),
        &session_id,
        &turn_id,
        &user_message,
        job_id,
    );

    let reopened = SqliteStore::open(database.path()).await.unwrap();
    reopened.readiness().await.unwrap();
    reopened
        .create_session_for_actor(
            "user-owner",
            CreateSessionRequest {
                id: "zz-normal-session".into(),
                title: "Normal Session".into(),
            },
            "create-normal-session-after-legacy-reopen",
        )
        .await
        .unwrap();
    let connection = rusqlite::Connection::open(database.path()).unwrap();
    connection
        .execute(
            "UPDATE sessions SET updated_at = ?1 WHERE id IN (?2, ?3)",
            params!["2026-08-27T00:00:00.000Z", session_id, "zz-normal-session"],
        )
        .unwrap();
    drop(connection);

    let first_page = reopened
        .session_summary_page_for_actor("user-owner", None, 1)
        .await
        .unwrap();
    assert_eq!(first_page.items[0].id, session_id);
    let second_page = reopened
        .session_summary_page_for_actor("user-owner", first_page.next_cursor.as_deref(), 1)
        .await
        .unwrap();
    assert_eq!(second_page.items[0].id, "zz-normal-session");
    assert!(second_page.next_cursor.is_none());
    assert!(
        reopened
            .list_sessions_for_actor("user-owner")
            .await
            .unwrap()
            .iter()
            .any(|session| session.id == session_id)
    );
    let detail = reopened
        .get_session_for_actor("user-owner", &session_id)
        .await
        .unwrap();
    assert_eq!(detail.session.sequence, 2);
    assert_eq!(detail.turns[0].id, turn_id);
    assert_eq!(detail.turns[0].user_message, user_message);
    assert_eq!(
        reopened
            .session_turn_for_actor("user-owner", &session_id, &turn_id)
            .await
            .unwrap(),
        detail.turns[0]
    );
    assert!(
        detail.events[..2]
            .iter()
            .all(|event| event.id.len() > protocol::RESOURCE_ID_MAX_BYTES),
        "legacy derived event IDs must remain readable"
    );
    assert_eq!(
        reopened
            .session_events_after_for_actor("user-owner", &session_id, 0)
            .await
            .unwrap(),
        detail.events
    );
    let legacy_page = reopened
        .session_event_page_for_actor("user-owner", &session_id, 0, 2)
        .await
        .unwrap();
    assert_eq!(legacy_page.items, detail.events);
    assert_eq!(legacy_page.next_after, None);
    assert_eq!(legacy_page.head_sequence, 2);
    assert!(!legacy_page.has_more);

    let ReplyClaimOutcome::Claimed(claimed) = reopened.claim_next_reply().await.unwrap() else {
        panic!("the legacy queued reply must remain claimable");
    };
    assert_eq!(claimed.session_id, session_id);
    assert_eq!(claimed.turn_id, turn_id);
    assert_eq!(claimed.status, ReplyJobStatus::Started);
    let completion = reopened
        .complete_reply_failure(ReplyFailureCommit {
            job_id: job_id.into(),
            expected_sequence: 2,
            error_json: json!({
                "code": "persisted_request_exceeds_resource_envelope",
                "message": "legacy provider input was rejected before execution",
            }),
        })
        .await
        .unwrap();
    assert_eq!(completion.job.status, ReplyJobStatus::Failed);
    assert_eq!(completion.session.status, SessionStatus::NeedsAttention);
    assert_eq!(completion.turn.status, SessionTurnStatus::Interrupted);
    assert_eq!(completion.events.len(), 1);
    assert_eq!(completion.events[0].id, "sev-3");
    assert!(completion.events[0].id.len() <= protocol::RESOURCE_ID_MAX_BYTES);
    assert!(matches!(
        completion.events[0].data,
        SessionEventData::TurnInterrupted { .. }
    ));

    let settled = reopened.get_session(&session_id).await.unwrap();
    assert_eq!(settled.session.status, SessionStatus::NeedsAttention);
    assert_eq!(settled.events.len(), 3);
    assert_eq!(settled.events.last().unwrap().id, "sev-3");
}

#[tokio::test]
async fn actor_scoped_session_and_run_reads_hide_foreign_or_disabled_resources() {
    let database = TestDatabase::new();
    let store = seeded_file_store(database.path()).await;
    store
        .seed_demo_session("session-ZR-1842", "Checkout API latency", RUN_ID)
        .await
        .unwrap();
    bootstrap_test_owner(&store).await;

    let sessions = store.list_sessions_for_actor("user-owner").await.unwrap();
    assert_eq!(sessions.len(), 1);
    let session_id = &sessions[0].id;
    assert_eq!(
        store
            .get_session_for_actor("user-owner", session_id)
            .await
            .unwrap()
            .run_ids,
        vec![RUN_ID]
    );
    assert!(matches!(
        store
            .get_session_for_actor("foreign-user", session_id)
            .await,
        Err(StorageError::SessionNotFound(id)) if id == *session_id
    ));
    assert!(matches!(
        store
            .session_events_after_for_actor("foreign-user", session_id, 0)
            .await,
        Err(StorageError::SessionNotFound(id)) if id == *session_id
    ));
    assert_eq!(
        store
            .snapshot_for_actor("user-owner", RUN_ID)
            .await
            .unwrap()
            .run
            .id,
        RUN_ID
    );
    assert!(matches!(
        store.snapshot_for_actor("foreign-user", RUN_ID).await,
        Err(StorageError::RunNotFound(id)) if id == RUN_ID
    ));
    assert!(matches!(
        store.load_run_for_actor("foreign-user", RUN_ID).await,
        Err(StorageError::RunNotFound(id)) if id == RUN_ID
    ));
    assert!(matches!(
        store
            .events_after_for_actor("foreign-user", RUN_ID, 0)
            .await,
        Err(StorageError::RunNotFound(id)) if id == RUN_ID
    ));

    set_test_user_status(database.path(), "user-owner", "disabled");
    assert!(matches!(
        store.get_session_for_actor("user-owner", session_id).await,
        Err(StorageError::SessionNotFound(_))
    ));
    assert!(matches!(
        store.snapshot_for_actor("user-owner", RUN_ID).await,
        Err(StorageError::RunNotFound(_))
    ));
}

#[tokio::test]
async fn actor_session_summary_pages_are_stable_bounded_and_indexed() {
    let database = TestDatabase::new();
    let store = SqliteStore::open(database.path()).await.unwrap();
    bootstrap_test_owner(&store).await;

    for index in 0..101 {
        let id = format!("session-page-{index:03}");
        store
            .create_session_for_actor(
                "user-owner",
                CreateSessionRequest {
                    id: id.clone(),
                    title: format!("Page fixture {index:03}"),
                },
                &format!("create-{id}"),
            )
            .await
            .unwrap();
    }

    let timestamp = "2026-08-27T00:00:00.000Z";
    let connection = rusqlite::Connection::open(database.path()).unwrap();
    assert_eq!(
        connection
            .execute(
                "UPDATE sessions SET updated_at = ?1 WHERE owner_user_id = ?2",
                params![timestamp, "user-owner"],
            )
            .unwrap(),
        101
    );
    let plan = explain_query_plan(
        &connection,
        r#"SELECT id, updated_at FROM sessions
           WHERE owner_user_id = ?1
             AND (updated_at < ?2 OR (updated_at = ?2 AND id > ?3))
           ORDER BY updated_at DESC, id ASC
           LIMIT ?4"#,
        params!["user-owner", timestamp, "session-page-049", 51_i64],
    );
    assert!(
        plan.contains("sessions_owner_updated_idx"),
        "unexpected Session keyset plan: {plan}"
    );
    drop(connection);

    let mut cursor = None;
    let mut first_owner_cursor = None;
    let mut ids = Vec::new();
    for (page_index, expected_len) in [50, 50, 1].into_iter().enumerate() {
        let page = store
            .session_summary_page_for_actor("user-owner", cursor.as_deref(), 50)
            .await
            .unwrap();
        assert_eq!(page.items.len(), expected_len);
        ids.extend(page.items.into_iter().map(|session| session.id));
        if page_index < 2 {
            assert!(page.next_cursor.is_some());
        } else {
            assert!(page.next_cursor.is_none());
        }
        if page_index == 0 {
            first_owner_cursor = page.next_cursor.clone();
        }
        cursor = page.next_cursor;
    }
    assert_eq!(
        ids,
        (0..101)
            .map(|index| format!("session-page-{index:03}"))
            .collect::<Vec<_>>()
    );

    for invalid_limit in [0, protocol::COLLECTION_PAGE_MAX_LIMIT + 1] {
        assert!(matches!(
            store
                .session_summary_page_for_actor("user-owner", None, invalid_limit)
                .await,
            Err(StorageError::InvalidPageLimit { limit, max })
                if limit == invalid_limit && max == protocol::COLLECTION_PAGE_MAX_LIMIT
        ));
    }
    assert!(matches!(
        store
            .session_summary_page_for_actor("user-owner", Some("not-a-cursor"), 50)
            .await,
        Err(StorageError::InvalidPageCursor)
    ));

    insert_test_member(database.path(), "foreign-user", "foreign");
    assert!(matches!(
        store
            .session_summary_page_for_actor("foreign-user", first_owner_cursor.as_deref(), 50,)
            .await,
        Err(StorageError::InvalidPageCursor)
    ));
    assert!(matches!(
        store
            .session_detail_page_for_actor(
                "foreign-user",
                "session-page-000",
                Some("not-a-cursor"),
                0,
                Some("not-a-cursor"),
                0,
                Some("not-a-cursor"),
                0,
            )
            .await,
        Err(StorageError::SessionNotFound(id)) if id == "session-page-000"
    ));
}

#[tokio::test]
async fn actor_session_detail_tails_are_independent_scoped_and_contiguous() {
    let database = TestDatabase::new();
    let store = seeded_file_store(database.path()).await;
    bootstrap_test_owner(&store).await;
    insert_second_run(database.path());
    let connection = rusqlite::Connection::open(database.path()).unwrap();
    assert_eq!(
        connection
            .execute(
                "UPDATE runs SET owner_user_id = ?1 WHERE id = 'ZR-SECOND'",
                ["user-owner"],
            )
            .unwrap(),
        1
    );
    drop(connection);
    for id in ["session-tail", "session-other"] {
        store
            .create_session_for_actor(
                "user-owner",
                CreateSessionRequest {
                    id: id.into(),
                    title: format!("Tail fixture {id}"),
                },
                &format!("create-{id}"),
            )
            .await
            .unwrap();
    }

    let mut sequence = 1;
    for (index, run_id) in [RUN_ID, "ZR-SECOND"].into_iter().enumerate() {
        let attached = store
            .attach_run_for_actor(
                "user-owner",
                "session-tail",
                AttachRunRequest {
                    run_id: run_id.into(),
                    expected_sequence: sequence,
                },
                &format!("attach-{index}"),
            )
            .await
            .unwrap();
        sequence = attached.session.sequence;
    }
    for ordinal in 1..=3 {
        let turn_id = format!("turn-{ordinal}");
        let started = store
            .start_turn_for_actor(
                "user-owner",
                "session-tail",
                StartTurnRequest {
                    turn_id: turn_id.clone(),
                    user_message: format!("message {ordinal}"),
                    expected_sequence: sequence,
                },
                &format!("start-{ordinal}"),
            )
            .await
            .unwrap();
        sequence = started.session.sequence;
        let flushed = store
            .flush_turn_for_actor(
                "user-owner",
                "session-tail",
                FlushSessionRequest {
                    turn_id,
                    assistant_message: Some(format!("answer {ordinal}")),
                    expected_sequence: sequence,
                },
                &format!("flush-{ordinal}"),
            )
            .await
            .unwrap();
        sequence = flushed.session.sequence;
    }
    assert_eq!(sequence, 12);

    let first = store
        .session_detail_page_for_actor("user-owner", "session-tail", None, 1, None, 2, None, 2)
        .await
        .unwrap();
    assert_eq!(first.session.sequence, 12);
    assert_eq!(first.run_ids.len(), 1);
    assert_eq!(
        first
            .turns
            .iter()
            .map(|turn| turn.ordinal)
            .collect::<Vec<_>>(),
        vec![2, 3]
    );
    assert_eq!(
        first
            .events
            .iter()
            .map(|event| event.sequence)
            .collect::<Vec<_>>(),
        vec![11, 12]
    );
    let first_pagination = first.pagination.as_ref().unwrap();
    assert!(first_pagination.run_ids.has_more);
    assert!(first_pagination.turns.has_more);
    assert!(first_pagination.events.has_more);

    let run_ids_before = first_pagination.run_ids.next_before.clone().unwrap();
    let older_run_ids = store
        .session_detail_page_for_actor(
            "user-owner",
            "session-tail",
            Some(&run_ids_before),
            1,
            None,
            2,
            None,
            2,
        )
        .await
        .unwrap();
    assert_eq!(older_run_ids.run_ids.len(), 1);
    assert_ne!(older_run_ids.run_ids, first.run_ids);
    assert!(!older_run_ids.pagination.unwrap().run_ids.has_more);

    assert!(matches!(
        store
            .session_detail_page_for_actor(
                "user-owner",
                "session-other",
                Some(&run_ids_before),
                1,
                None,
                2,
                None,
                2,
            )
            .await,
        Err(StorageError::InvalidPageCursor)
    ));

    let turns_before = first_pagination.turns.next_before.clone().unwrap();
    let older_turns = store
        .session_detail_page_for_actor(
            "user-owner",
            "session-tail",
            None,
            1,
            Some(&turns_before),
            2,
            None,
            2,
        )
        .await
        .unwrap();
    assert_eq!(older_turns.turns.len(), 1);
    assert_eq!(older_turns.turns[0].ordinal, 1);
    assert!(!older_turns.pagination.unwrap().turns.has_more);

    let first_events_before = first_pagination.events.next_before.clone().unwrap();
    let mut event_sequences = first
        .events
        .iter()
        .map(|event| event.sequence)
        .collect::<Vec<_>>();
    let mut events_before = Some(first_events_before.clone());
    while let Some(before) = events_before {
        let page = store
            .session_detail_page_for_actor(
                "user-owner",
                "session-tail",
                None,
                1,
                None,
                2,
                Some(&before),
                2,
            )
            .await
            .unwrap();
        assert!(
            page.events
                .windows(2)
                .all(|pair| pair[0].sequence < pair[1].sequence)
        );
        event_sequences.extend(page.events.iter().map(|event| event.sequence));
        events_before = page.pagination.unwrap().events.next_before;
    }
    event_sequences.sort_unstable();
    assert_eq!(event_sequences, (1..=12).collect::<Vec<_>>());

    assert!(matches!(
        store
            .session_detail_page_for_actor(
                "user-owner",
                "session-other",
                None,
                1,
                None,
                2,
                Some(&first_events_before),
                2,
            )
            .await,
        Err(StorageError::InvalidPageCursor)
    ));
    assert!(matches!(
        store
            .session_detail_page_for_actor(
                "user-owner",
                "session-tail",
                None,
                1,
                None,
                2,
                Some("not-a-cursor"),
                2,
            )
            .await,
        Err(StorageError::InvalidPageCursor)
    ));
    for (run_ids_limit, turns_limit, events_limit, expected_max) in [
        (0, 2, 2, protocol::COLLECTION_PAGE_MAX_LIMIT),
        (
            1,
            protocol::COLLECTION_PAGE_MAX_LIMIT + 1,
            2,
            protocol::COLLECTION_PAGE_MAX_LIMIT,
        ),
        (
            1,
            2,
            protocol::EVENT_PAGE_MAX_LIMIT + 1,
            protocol::EVENT_PAGE_MAX_LIMIT,
        ),
    ] {
        assert!(matches!(
            store
                .session_detail_page_for_actor(
                    "user-owner",
                    "session-tail",
                    None,
                    run_ids_limit,
                    None,
                    turns_limit,
                    None,
                    events_limit,
                )
                .await,
            Err(StorageError::InvalidPageLimit { max, .. }) if max == expected_max
        ));
    }
    let future = crate::cursor::encode_session_events("session-tail", sequence + 1).unwrap();
    assert!(matches!(
        store
            .session_detail_page_for_actor(
                "user-owner",
                "session-tail",
                None,
                1,
                None,
                2,
                Some(&future),
                2,
            )
            .await,
        Err(StorageError::PageCursorBeyondHead { head }) if head == sequence
    ));

    insert_test_member(database.path(), "foreign-user", "foreign");
    assert!(matches!(
        store
            .session_detail_page_for_actor(
                "foreign-user",
                "session-tail",
                Some("not-a-cursor"),
                0,
                Some("not-a-cursor"),
                0,
                Some("not-a-cursor"),
                0,
            )
            .await,
        Err(StorageError::SessionNotFound(id)) if id == "session-tail"
    ));

    let connection = rusqlite::Connection::open(database.path()).unwrap();
    let event_plan = explain_query_plan(
        &connection,
        r#"SELECT sequence FROM session_events
           WHERE session_id = ?1 AND sequence < ?2
           ORDER BY sequence DESC LIMIT ?3"#,
        params!["session-tail", 9_i64, 3_i64],
    );
    assert!(
        event_plan.contains("SEARCH session_events USING PRIMARY KEY"),
        "unexpected Session event-tail plan: {event_plan}"
    );
    let attachment_plan = explain_query_plan(
        &connection,
        r#"SELECT run_id, attached_at FROM session_runs
           WHERE session_id = ?1 AND attached_at < ?2
           ORDER BY attached_at DESC, run_id DESC LIMIT ?3"#,
        params!["session-tail", "9999-12-31T23:59:59Z", 2_i64],
    );
    assert!(
        attachment_plan.contains("session_runs_session_attached_idx"),
        "unexpected Run-attachment tail plan: {attachment_plan}"
    );
}

#[tokio::test]
async fn actor_bounded_run_reads_latest_tail_with_scoped_cursor_and_one_head() {
    let total = protocol::EVENT_PAGE_MAX_LIMIT + 2;
    let store = bounded_event_store(total).await;

    let first = store
        .bounded_run_for_actor("user-owner", RUN_ID, None, 128)
        .await
        .unwrap();
    assert_eq!(first.snapshot.run.sequence, total as u64);
    assert_eq!(first.events.len(), 128);
    assert_eq!(first.events.first().unwrap().sequence, 131);
    assert_eq!(first.events.last().unwrap().sequence, 258);
    assert!(first.events_page.has_more);
    let first_before = first.events_page.next_before.unwrap();

    let second = store
        .bounded_run_for_actor("user-owner", RUN_ID, Some(&first_before), 128)
        .await
        .unwrap();
    assert_eq!(second.snapshot.run.sequence, total as u64);
    assert_eq!(second.events.first().unwrap().sequence, 3);
    assert_eq!(second.events.last().unwrap().sequence, 130);
    assert!(second.events_page.has_more);
    let second_before = second.events_page.next_before.unwrap();

    let third = store
        .bounded_run_for_actor("user-owner", RUN_ID, Some(&second_before), 128)
        .await
        .unwrap();
    assert_eq!(
        third
            .events
            .iter()
            .map(|event| event.sequence)
            .collect::<Vec<_>>(),
        vec![1, 2]
    );
    assert!(!third.events_page.has_more);
    assert!(third.events_page.next_before.is_none());

    for invalid_limit in [0, protocol::EVENT_PAGE_MAX_LIMIT + 1] {
        assert!(matches!(
            store
                .bounded_run_for_actor("user-owner", RUN_ID, None, invalid_limit)
                .await,
            Err(StorageError::InvalidPageLimit { limit, max })
                if limit == invalid_limit && max == protocol::EVENT_PAGE_MAX_LIMIT
        ));
    }
    assert!(matches!(
        store
            .bounded_run_for_actor("user-owner", RUN_ID, Some("not-a-cursor"), 2)
            .await,
        Err(StorageError::InvalidPageCursor)
    ));
    assert!(matches!(
        store
            .bounded_run_for_actor("user-owner", RUN_ID, Some(&(first_before.clone() + "=")), 2,)
            .await,
        Err(StorageError::InvalidPageCursor)
    ));
    let wrong_kind = crate::cursor::encode_session_events("session-tail", 2).unwrap();
    assert!(matches!(
        store
            .bounded_run_for_actor("user-owner", RUN_ID, Some(&wrong_kind), 2)
            .await,
        Err(StorageError::InvalidPageCursor)
    ));
    let future = crate::cursor::encode_run_events(RUN_ID, total as u64 + 1).unwrap();
    assert!(matches!(
        store
            .bounded_run_for_actor("user-owner", RUN_ID, Some(&future), 2)
            .await,
        Err(StorageError::PageCursorBeyondHead { head }) if head == total as u64
    ));
    assert!(matches!(
        store
            .bounded_run_for_actor("foreign-user", RUN_ID, Some("not-a-cursor"), 0)
            .await,
        Err(StorageError::RunNotFound(id)) if id == RUN_ID
    ));
}

#[tokio::test]
async fn actor_scoped_run_event_pages_are_bounded_contiguous_and_cursor_safe() {
    let total = protocol::EVENT_PAGE_MAX_LIMIT + 2;
    let store = bounded_event_store(total).await;

    let first = store
        .run_event_page_for_actor("user-owner", RUN_ID, 0, protocol::EVENT_PAGE_MAX_LIMIT)
        .await
        .unwrap();
    assert_eq!(first.items.len(), protocol::EVENT_PAGE_MAX_LIMIT);
    assert_eq!(first.items.first().unwrap().sequence, 1);
    assert_eq!(first.items.last().unwrap().sequence, 256);
    assert_eq!(first.next_after, Some(256));
    assert_eq!(first.head_sequence, total as u64);
    assert!(first.has_more);

    let second = store
        .run_event_page_for_actor(
            "user-owner",
            RUN_ID,
            first.next_after.unwrap(),
            protocol::EVENT_PAGE_MAX_LIMIT,
        )
        .await
        .unwrap();
    assert_eq!(
        second
            .items
            .iter()
            .map(|event| event.sequence)
            .collect::<Vec<_>>(),
        vec![257, 258]
    );
    assert_eq!(second.next_after, None);
    assert_eq!(second.head_sequence, total as u64);
    assert!(!second.has_more);

    let empty = store
        .run_event_page_for_actor(
            "user-owner",
            RUN_ID,
            total as u64,
            protocol::EVENT_PAGE_DEFAULT_LIMIT,
        )
        .await
        .unwrap();
    assert!(empty.items.is_empty());
    assert_eq!(empty.next_after, None);
    assert_eq!(empty.head_sequence, total as u64);
    assert!(!empty.has_more);

    assert!(matches!(
        store
            .run_event_page_for_actor("user-owner", RUN_ID, total as u64 + 1, 1)
            .await,
        Err(StorageError::EventCursorBeyondHead {
            after,
            head_sequence,
        }) if after == total as u64 + 1 && head_sequence == total as u64
    ));
    assert!(matches!(
        store
            .run_event_page_for_actor("user-owner", RUN_ID, u64::MAX, 1)
            .await,
        Err(StorageError::EventCursorOutOfRange { after }) if after == u64::MAX
    ));
    for invalid_limit in [0, protocol::EVENT_PAGE_MAX_LIMIT + 1] {
        assert!(matches!(
            store
                .run_event_page_for_actor("user-owner", RUN_ID, 0, invalid_limit)
                .await,
            Err(StorageError::InvalidEventPageLimit { limit, max })
                if limit == invalid_limit && max == protocol::EVENT_PAGE_MAX_LIMIT
        ));
    }

    assert!(matches!(
        store
            .run_event_page_for_actor("foreign-user", RUN_ID, total as u64 + 1, 1)
            .await,
        Err(StorageError::RunNotFound(id)) if id == RUN_ID
    ));
    assert!(matches!(
        store
            .run_event_page_for_actor("foreign-user", RUN_ID, 0, 0)
            .await,
        Err(StorageError::RunNotFound(id)) if id == RUN_ID
    ));
}

#[tokio::test]
async fn run_event_pages_fail_closed_when_the_projection_head_is_inconsistent() {
    let database = TestDatabase::new();
    let store = seeded_file_store(database.path()).await;

    let connection = rusqlite::Connection::open(database.path()).unwrap();
    connection
        .execute(
            "UPDATE runs SET projection_sequence = sequence - 1 WHERE id = ?1",
            [RUN_ID],
        )
        .unwrap();
    drop(connection);

    assert!(matches!(
        store.run_event_page(RUN_ID, 0, 1).await,
        Err(StorageError::CorruptData(message))
            if message.contains("projection sequence") && message.contains("run head")
    ));
}

#[tokio::test]
async fn actor_scoped_session_event_pages_authorize_before_page_validation() {
    let store = seeded_store().await;
    store
        .seed_demo_session("session-ZR-1842", "Checkout API latency", RUN_ID)
        .await
        .unwrap();
    bootstrap_test_owner(&store).await;

    let first = store
        .session_event_page_for_actor("user-owner", "session-ZR-1842", 0, 1)
        .await
        .unwrap();
    assert_eq!(first.items.len(), 1);
    assert_eq!(first.items[0].sequence, 1);
    assert_eq!(first.next_after, Some(1));
    assert_eq!(first.head_sequence, 2);
    assert!(first.has_more);

    let last = store
        .session_event_page_for_actor("user-owner", "session-ZR-1842", 1, 1)
        .await
        .unwrap();
    assert_eq!(last.items.len(), 1);
    assert_eq!(last.items[0].sequence, 2);
    assert_eq!(last.next_after, None);
    assert_eq!(last.head_sequence, 2);
    assert!(!last.has_more);

    assert!(matches!(
        store
            .session_event_page_for_actor("user-owner", "session-ZR-1842", 3, 1)
            .await,
        Err(StorageError::EventCursorBeyondHead {
            after: 3,
            head_sequence: 2,
        })
    ));
    assert!(matches!(
        store
            .session_event_page_for_actor("foreign-user", "session-ZR-1842", 3, 0)
            .await,
        Err(StorageError::SessionNotFound(id)) if id == "session-ZR-1842"
    ));
}

#[tokio::test]
async fn run_event_page_does_not_decode_past_limit_plus_one() {
    let database = TestDatabase::new();
    let total = protocol::EVENT_PAGE_MAX_LIMIT + 2;
    let store = SqliteStore::open(database.path()).await.unwrap();
    seed_event_count(&store, total).await;

    let connection = rusqlite::Connection::open(database.path()).unwrap();
    connection
        .execute_batch("DROP TRIGGER run_events_reject_update;")
        .unwrap();
    connection
        .execute(
            "UPDATE run_events SET payload_json = ?1 WHERE run_id = ?2 AND sequence = ?3",
            params!["{}", RUN_ID, total as i64],
        )
        .unwrap();
    drop(connection);

    let first = store
        .run_event_page(RUN_ID, 0, protocol::EVENT_PAGE_MAX_LIMIT)
        .await
        .unwrap();
    assert_eq!(first.items.len(), protocol::EVENT_PAGE_MAX_LIMIT);
    assert_eq!(first.next_after, Some(256));
    assert!(first.has_more);

    assert!(matches!(
        store
            .run_event_page(
                RUN_ID,
                first.next_after.unwrap(),
                protocol::EVENT_PAGE_MAX_LIMIT,
            )
            .await,
        Err(StorageError::Json(_))
    ));
}

#[tokio::test]
async fn active_owner_and_member_have_independent_session_receipt_namespaces() {
    let database = TestDatabase::new();
    let store = SqliteStore::open(database.path()).await.unwrap();
    bootstrap_test_owner(&store).await;
    insert_test_member(database.path(), "user-member", "member");

    let owner = store
        .create_session_for_actor(
            "user-owner",
            CreateSessionRequest {
                id: "session-owner-scope".into(),
                title: "Owner scope".into(),
            },
            "shared-create-key",
        )
        .await
        .unwrap();
    let member = store
        .create_session_for_actor(
            "user-member",
            CreateSessionRequest {
                id: "session-member-scope".into(),
                title: "Member scope".into(),
            },
            "shared-create-key",
        )
        .await
        .unwrap();
    assert_eq!(owner.session.id, "session-owner-scope");
    assert_eq!(member.session.id, "session-member-scope");

    let owner_turn = store
        .start_turn_for_actor(
            "user-owner",
            "session-owner-scope",
            StartTurnRequest {
                turn_id: "turn-owner-scope".into(),
                user_message: "Owner turn".into(),
                expected_sequence: 1,
            },
            "shared-turn-key",
        )
        .await
        .unwrap();
    let member_turn = store
        .start_turn_for_actor(
            "user-member",
            "session-member-scope",
            StartTurnRequest {
                turn_id: "turn-member-scope".into(),
                user_message: "Member turn".into(),
                expected_sequence: 1,
            },
            "shared-turn-key",
        )
        .await
        .unwrap();
    assert_eq!(owner_turn.turn.id, "turn-owner-scope");
    assert_eq!(member_turn.turn.id, "turn-member-scope");
    assert_eq!(
        store
            .session_turn_for_actor("user-owner", "session-owner-scope", "turn-owner-scope",)
            .await
            .unwrap(),
        owner_turn.turn
    );
    assert!(matches!(
        store
            .session_turn_for_actor(
                "user-member",
                "session-owner-scope",
                " malformed-turn ",
            )
            .await,
        Err(StorageError::SessionNotFound(id)) if id == "session-owner-scope"
    ));
    assert!(matches!(
        store
            .session_turn_for_actor(
                "user-owner",
                "session-owner-scope",
                "unknown-turn",
            )
            .await,
        Err(StorageError::SessionTurnNotFound(id)) if id == "unknown-turn"
    ));
    assert!(matches!(
        store
            .get_session_for_actor("user-member", "session-owner-scope")
            .await,
        Err(StorageError::SessionNotFound(_))
    ));
    store.readiness().await.unwrap();
}

#[tokio::test]
async fn actor_scoped_resume_authorizes_before_receipt_replay() {
    let store = created_owned_session_store().await;
    store
        .start_turn_for_actor(
            "user-owner",
            "session-alpha",
            StartTurnRequest {
                turn_id: "turn-resume-actor".into(),
                user_message: "Interrupt this turn".into(),
                expected_sequence: 1,
            },
            "start-resume-actor",
        )
        .await
        .unwrap();
    let recovered = store.recover_open_turns().await.unwrap();
    assert_eq!(recovered.len(), 1);
    let request = ResumeSessionRequest {
        expected_sequence: 3,
    };
    assert!(matches!(
        store
            .resume_session_for_actor(
                "foreign-user",
                "session-alpha",
                request.clone(),
                "resume-shared-key",
            )
            .await,
        Err(StorageError::SessionNotFound(_))
    ));
    let resumed = store
        .resume_session_for_actor(
            "user-owner",
            "session-alpha",
            request.clone(),
            "resume-shared-key",
        )
        .await
        .unwrap();
    assert!(!resumed.replayed);
    assert!(
        store
            .resume_session_for_actor("user-owner", "session-alpha", request, "resume-shared-key",)
            .await
            .unwrap()
            .replayed
    );
}

#[tokio::test]
async fn review_receipts_are_actor_scoped_and_authorization_precedes_replay() {
    let database = TestDatabase::new();
    let store = seeded_file_store(database.path()).await;
    bootstrap_test_owner(&store).await;
    let (snapshot, _) = seed_fixture();
    let commit = approved_commit(&snapshot, "actor-review");

    assert_eq!(
        store
            .commit_review_for_actor("user-owner", commit.clone())
            .await
            .unwrap(),
        CommitOutcome::Committed
    );
    assert!(
        store
            .review_receipt_for_actor("user-owner", RUN_ID, "actor-review")
            .await
            .unwrap()
            .is_some()
    );
    assert!(matches!(
        store
            .review_receipt_for_actor("foreign-user", RUN_ID, "actor-review")
            .await,
        Err(StorageError::RunNotFound(_))
    ));

    set_test_user_status(database.path(), "user-owner", "disabled");
    assert!(matches!(
        store.commit_review_for_actor("user-owner", commit).await,
        Err(StorageError::RunNotFound(_))
    ));
    assert_eq!(store.load_run(RUN_ID).await.unwrap().events.len(), 7);
}

#[tokio::test]
async fn reply_claim_rechecks_actor_and_interrupts_without_provider_execution() {
    let database = TestDatabase::new();
    let store = created_owned_file_session_store(database.path()).await;
    store
        .start_turn_and_enqueue_reply_for_actor(
            "user-owner",
            "session-alpha",
            StartTurnRequest {
                turn_id: "turn-revoked-reply".into(),
                user_message: "Do not send this after authorization changes".into(),
                expected_sequence: 1,
            },
            "start-revoked-reply",
            reply_job_spec("reply-revoked", "turn-revoked-reply"),
        )
        .await
        .unwrap();
    set_test_user_status(database.path(), "user-owner", "disabled");

    let ReplyClaimOutcome::Rejected(completion) = store.claim_next_reply().await.unwrap() else {
        panic!("a disabled actor must be rejected before provider execution");
    };
    assert_eq!(completion.job.status, ReplyJobStatus::Failed);
    assert_eq!(completion.job.attempt, 1);
    assert_eq!(completion.session.status, SessionStatus::NeedsAttention);
    assert_eq!(completion.turn.status, SessionTurnStatus::Interrupted);
    assert_eq!(completion.events.len(), 1);
    assert!(matches!(
        completion.events[0].data,
        SessionEventData::TurnInterrupted { .. }
    ));
    assert_eq!(
        store.claim_next_reply().await.unwrap(),
        ReplyClaimOutcome::NotAvailable
    );
}

#[tokio::test]
async fn dispatch_claim_rechecks_owner_and_records_not_dispatched_evidence() {
    let database = TestDatabase::new();
    let store = seeded_file_store(database.path()).await;
    bootstrap_test_owner(&store).await;
    let (snapshot, _) = seed_fixture();
    let review = approved_dispatch_commit(&snapshot, "revoked-dispatch");
    store
        .commit_review_for_actor("user-owner", review.clone())
        .await
        .unwrap();
    set_test_user_role(database.path(), "user-owner", "member");

    let ClaimOutcome::Rejected(rejection) = store
        .claim_next_dispatch(start_commit(&review.snapshot))
        .await
        .unwrap()
    else {
        panic!("an approving actor demoted to member must never reach a connector");
    };
    assert_eq!(rejection.job.status, DispatchStatus::Rejected);
    assert_eq!(rejection.job.attempt, 0);
    assert_eq!(rejection.job.start_event_sequence, None);
    assert_eq!(rejection.job.result_event_sequence, Some(8));
    assert_eq!(
        rejection.job.authorization_error_json.as_ref().unwrap()["reason"],
        "approving_actor_role_changed"
    );
    assert_eq!(rejection.event.metadata["executor_invoked"], false);
    assert!(matches!(
        rejection.event.data.as_ref(),
        Some(RunEventData::ToolResult {
            outcome: ToolOutcome::NotDispatched {
                reason: NotDispatchedReason::AuthorizationRevoked,
                ..
            },
            status: ToolCallStatus::NotDispatched,
            ..
        })
    ));
    let stored = store.load_run(RUN_ID).await.unwrap();
    assert_eq!(stored.snapshot.run.status, RunStatus::NeedsAttention);
    assert_eq!(stored.snapshot.run.sequence, 8);
    assert_eq!(stored.events.last(), Some(&rejection.event));
    assert!(store.started_dispatches().await.unwrap().is_empty());
    assert_eq!(
        store
            .claim_next_dispatch(start_commit(&review.snapshot))
            .await
            .unwrap(),
        ClaimOutcome::NotAvailable
    );
    assert!(matches!(
        store.verify_integrity().await,
        Err(StorageError::CorruptData(message))
            if message.contains("exactly one owner")
    ));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_reply_claims_execute_one_job_at_most_once() {
    let database = TestDatabase::new();
    let store = created_owned_file_session_store(database.path()).await;
    store
        .start_turn_and_enqueue_reply(
            "session-alpha",
            StartTurnRequest {
                turn_id: "turn-concurrent-reply".into(),
                user_message: "Only one worker may execute this".into(),
                expected_sequence: 1,
            },
            "start-concurrent-reply",
            reply_job_spec("reply-concurrent", "turn-concurrent-reply"),
        )
        .await
        .unwrap();

    let mut tasks = Vec::new();
    for _ in 0..8 {
        let store = store.clone();
        tasks.push(tokio::spawn(async move { store.claim_next_reply().await }));
    }
    let mut claimed = 0;
    let mut unavailable = 0;
    for task in tasks {
        match task.await.unwrap().unwrap() {
            ReplyClaimOutcome::Claimed(job) => {
                claimed += 1;
                assert_eq!(job.id, "reply-concurrent");
            }
            ReplyClaimOutcome::Rejected(_) => {
                panic!("the active session owner must remain authorized")
            }
            ReplyClaimOutcome::NotAvailable => unavailable += 1,
        }
    }
    assert_eq!(claimed, 1);
    assert_eq!(unavailable, 7);
    let stored = store.reply_job("reply-concurrent").await.unwrap().unwrap();
    assert_eq!(stored.status, ReplyJobStatus::Started);
    assert_eq!(stored.attempt, 1);
}

#[tokio::test]
async fn queued_reply_survives_restart_and_started_reply_recovers_outcome_unknown_once() {
    let database = TestDatabase::new();
    {
        let store = created_owned_file_session_store(database.path()).await;
        store
            .start_turn_and_enqueue_reply(
                "session-alpha",
                StartTurnRequest {
                    turn_id: "turn-reply-recovery".into(),
                    user_message: "Survive a process restart".into(),
                    expected_sequence: 1,
                },
                "start-reply-recovery",
                reply_job_spec("reply-recovery", "turn-reply-recovery"),
            )
            .await
            .unwrap();
    }

    {
        let reopened = SqliteStore::open(database.path()).await.unwrap();
        assert!(reopened.recover_open_turns().await.unwrap().is_empty());
        assert!(reopened.recover_started_replies().await.unwrap().is_empty());
        let ReplyClaimOutcome::Claimed(job) = reopened.claim_next_reply().await.unwrap() else {
            panic!("queued work must remain claimable after restart");
        };
        assert_eq!(job.id, "reply-recovery");
    }

    let reopened = SqliteStore::open(database.path()).await.unwrap();
    let recovered = reopened.recover_started_replies().await.unwrap();
    assert_eq!(recovered.len(), 1);
    assert_eq!(recovered[0].job.status, ReplyJobStatus::OutcomeUnknown);
    assert_eq!(recovered[0].session.status, SessionStatus::NeedsAttention);
    assert_eq!(recovered[0].session.sequence, 3);
    assert!(matches!(
        recovered[0].events[0].data,
        SessionEventData::TurnInterrupted { .. }
    ));
    assert!(reopened.recover_started_replies().await.unwrap().is_empty());
    assert!(reopened.recover_open_turns().await.unwrap().is_empty());
    assert!(matches!(
        reopened.claim_next_reply().await.unwrap(),
        ReplyClaimOutcome::NotAvailable
    ));
}

#[tokio::test]
async fn reply_failure_commits_interruption_and_replays_without_duplicate_events() {
    let store = created_owned_session_store().await;
    store
        .start_turn_and_enqueue_reply(
            "session-alpha",
            StartTurnRequest {
                turn_id: "turn-reply-failure".into(),
                user_message: "The provider will fail".into(),
                expected_sequence: 1,
            },
            "start-reply-failure",
            reply_job_spec("reply-failure", "turn-reply-failure"),
        )
        .await
        .unwrap();
    assert!(matches!(
        store.claim_next_reply().await.unwrap(),
        ReplyClaimOutcome::Claimed(_)
    ));
    let commit = ReplyFailureCommit {
        job_id: "reply-failure".into(),
        expected_sequence: 2,
        error_json: json!({
            "code": "provider_unauthorized",
            "message": "The reply provider rejected the request",
        }),
    };
    let failed = store.complete_reply_failure(commit.clone()).await.unwrap();
    assert_eq!(failed.job.status, ReplyJobStatus::Failed);
    assert_eq!(failed.session.status, SessionStatus::NeedsAttention);
    assert_eq!(failed.turn.status, SessionTurnStatus::Interrupted);
    assert_eq!(failed.events.len(), 1);
    assert!(
        store
            .complete_reply_failure(commit.clone())
            .await
            .unwrap()
            .replayed
    );
    let mut conflicting = commit;
    conflicting.error_json = json!({
        "code": "different",
        "message": "The reply provider rejected the request",
    });
    assert!(matches!(
        store.complete_reply_failure(conflicting).await,
        Err(StorageError::IdempotencyConflict)
    ));
    assert_eq!(
        store
            .get_session("session-alpha")
            .await
            .unwrap()
            .events
            .len(),
        3
    );
}

#[tokio::test]
async fn reply_outcome_unknown_commits_once_and_is_never_claimable_again() {
    let store = created_owned_session_store().await;
    store
        .start_turn_and_enqueue_reply(
            "session-alpha",
            StartTurnRequest {
                turn_id: "turn-reply-unknown".into(),
                user_message: "The transport outcome cannot be proven".into(),
                expected_sequence: 1,
            },
            "start-reply-unknown",
            reply_job_spec("reply-unknown", "turn-reply-unknown"),
        )
        .await
        .unwrap();
    assert!(matches!(
        store.claim_next_reply().await.unwrap(),
        ReplyClaimOutcome::Claimed(_)
    ));
    let commit = ReplyOutcomeUnknownCommit {
        job_id: "reply-unknown".into(),
        expected_sequence: 2,
        error_json: json!({
            "code": "provider_timeout",
            "message": "The reply provider request timed out",
        }),
    };

    let unknown = store
        .complete_reply_outcome_unknown(commit.clone())
        .await
        .unwrap();

    assert_eq!(unknown.job.status, ReplyJobStatus::OutcomeUnknown);
    assert_eq!(unknown.session.status, SessionStatus::NeedsAttention);
    assert_eq!(unknown.turn.status, SessionTurnStatus::Interrupted);
    assert_eq!(unknown.events.len(), 1);
    assert!(matches!(
        &unknown.events[0].data,
        SessionEventData::TurnInterrupted { reason, .. }
            if reason == "assistant reply provider outcome is unknown"
    ));
    assert!(
        store
            .complete_reply_outcome_unknown(commit.clone())
            .await
            .unwrap()
            .replayed
    );
    let mut conflicting = commit;
    conflicting.error_json = json!({
        "code": "provider_transport_failed",
        "message": "The reply provider transport failed",
    });
    assert!(matches!(
        store.complete_reply_outcome_unknown(conflicting).await,
        Err(StorageError::IdempotencyConflict)
    ));
    assert!(matches!(
        store.claim_next_reply().await.unwrap(),
        ReplyClaimOutcome::NotAvailable
    ));
}

#[tokio::test]
async fn reply_terminal_envelope_rejects_before_any_completion_mutation() {
    let store = created_owned_session_store().await;
    store
        .start_turn_and_enqueue_reply(
            "session-alpha",
            StartTurnRequest {
                turn_id: "turn-reply-envelope".into(),
                user_message: "Enforce the terminal envelope".into(),
                expected_sequence: 1,
            },
            "start-reply-envelope",
            reply_job_spec("reply-envelope", "turn-reply-envelope"),
        )
        .await
        .unwrap();
    assert!(matches!(
        store.claim_next_reply().await.unwrap(),
        ReplyClaimOutcome::Claimed(_)
    ));

    let mut mismatched = ReplySuccessCommit {
        job_id: "reply-envelope".into(),
        expected_sequence: 2,
        assistant_message: "Bounded assistant output".into(),
        provenance: AssistantReplyProvenance {
            provider_id: "test-provider".into(),
            model: Some("test-model".into()),
            reply_kind: AssistantReplyKind::Model,
        },
        response_json: model_reply_json("Different assistant output"),
    };
    assert!(matches!(
        store.complete_reply_success(mismatched.clone()).await,
        Err(StorageError::InvalidReplyTransition(_))
    ));

    mismatched.assistant_message = "x".repeat(protocol::ASSISTANT_MESSAGE_MAX_BYTES + 1);
    mismatched.response_json = model_reply_json(&mismatched.assistant_message);
    assert!(matches!(
        store.complete_reply_success(mismatched).await,
        Err(StorageError::InvalidSessionTransition(_))
    ));

    let mut invalid_provenance = ReplySuccessCommit {
        job_id: "reply-envelope".into(),
        expected_sequence: 2,
        assistant_message: "Bounded assistant output".into(),
        provenance: AssistantReplyProvenance {
            provider_id: "test-provider".into(),
            model: None,
            reply_kind: AssistantReplyKind::Model,
        },
        response_json: model_reply_json("Bounded assistant output"),
    };
    invalid_provenance.response_json["provider"]["model"] = Value::Null;
    assert!(matches!(
        store.complete_reply_success(invalid_provenance).await,
        Err(StorageError::InvalidReplyTransition(_))
    ));

    let invalid_non_model = ReplySuccessCommit {
        job_id: "reply-envelope".into(),
        expected_sequence: 2,
        assistant_message: "Bounded assistant output".into(),
        provenance: AssistantReplyProvenance {
            provider_id: "test-provider".into(),
            model: Some("test-model".into()),
            reply_kind: AssistantReplyKind::NonModelFallback,
        },
        response_json: json!({
            "content": "Bounded assistant output",
            "finish_reason": "stop",
            "provider": {
                "provider_id": "test-provider",
                "model": "test-model",
                "reply_kind": "non_model_fallback",
            },
        }),
    };
    assert!(matches!(
        store.complete_reply_success(invalid_non_model).await,
        Err(StorageError::InvalidReplyTransition(_))
    ));

    assert!(matches!(
        store
            .complete_reply_failure(ReplyFailureCommit {
                job_id: "reply-envelope".into(),
                expected_sequence: 2,
                error_json: json!({"code": "provider_failed"}),
            })
            .await,
        Err(StorageError::InvalidReplyTransition(_))
    ));
    let job = store.reply_job("reply-envelope").await.unwrap().unwrap();
    assert_eq!(job.status, ReplyJobStatus::Started);
    assert!(job.response_json.is_none());
    assert!(job.error_json.is_none());
    let detail = store.get_session("session-alpha").await.unwrap();
    assert_eq!(detail.session.sequence, 2);
    assert_eq!(detail.turns[0].status, SessionTurnStatus::Open);
}

#[tokio::test]
async fn non_model_reply_without_a_model_is_a_valid_terminal_provenance() {
    let store = created_owned_session_store().await;
    let mut job = reply_job_spec("reply-non-model", "turn-reply-non-model");
    job.model_name = None;
    store
        .start_turn_and_enqueue_reply(
            "session-alpha",
            StartTurnRequest {
                turn_id: "turn-reply-non-model".into(),
                user_message: "Use the bounded local fallback".into(),
                expected_sequence: 1,
            },
            "start-reply-non-model",
            job,
        )
        .await
        .unwrap();
    assert!(matches!(
        store.claim_next_reply().await.unwrap(),
        ReplyClaimOutcome::Claimed(_)
    ));

    let completion = store
        .complete_reply_success(ReplySuccessCommit {
            job_id: "reply-non-model".into(),
            expected_sequence: 2,
            assistant_message: "The local fallback completed safely.".into(),
            provenance: AssistantReplyProvenance {
                provider_id: "test-provider".into(),
                model: None,
                reply_kind: AssistantReplyKind::NonModelFallback,
            },
            response_json: json!({
                "content": "The local fallback completed safely.",
                "finish_reason": "stop",
                "provider": {
                    "provider_id": "test-provider",
                    "model": null,
                    "reply_kind": "non_model_fallback",
                },
            }),
        })
        .await
        .unwrap();
    assert_eq!(completion.job.status, ReplyJobStatus::Succeeded);
    assert!(matches!(
        completion.events[0].data,
        SessionEventData::AssistantMessage { .. }
    ));
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
    bootstrap_test_owner(&store).await;
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
async fn dispatch_admission_rejects_unclaimable_jobs_without_any_durable_side_effect() {
    let database = TestDatabase::new();
    let store = seeded_file_store(database.path()).await;
    bootstrap_test_owner(&store).await;
    store
        .bind_runtime_identity(production_identity())
        .await
        .unwrap();
    let (snapshot, _) = seed_fixture();
    let before = store.load_run(RUN_ID).await.unwrap();

    let mut valid = approved_dispatch_commit(&snapshot, "dispatch-admission-valid");
    let dispatch = valid.dispatch.as_mut().unwrap();
    dispatch.policy_id = "production-guarded".into();
    dispatch.policy_revision = "production-guarded/v1".into();
    valid.event.approval.as_mut().unwrap().policy_revision = Some(dispatch.policy_revision.clone());
    valid.response.event = valid.event.clone();

    let mut cases = Vec::new();

    let mut wrong_policy = valid.clone();
    wrong_policy.idempotency_key = "dispatch-admission-policy".into();
    wrong_policy.dispatch.as_mut().unwrap().policy_id = "local-development".into();
    cases.push(("wrong policy", wrong_policy));

    let mut wrong_version = valid.clone();
    wrong_version.idempotency_key = "dispatch-admission-version".into();
    wrong_version.dispatch.as_mut().unwrap().tool_version = "2.0.0".into();
    cases.push(("mismatched version", wrong_version));

    let mut wrong_arguments = valid.clone();
    wrong_arguments.idempotency_key = "dispatch-admission-arguments".into();
    wrong_arguments.dispatch.as_mut().unwrap().args_json = json!({"message": "changed"});
    cases.push(("mismatched arguments", wrong_arguments));

    let mut wrong_effect = valid.clone();
    wrong_effect.idempotency_key = "dispatch-admission-effect".into();
    wrong_effect.dispatch.as_mut().unwrap().effect = ToolEffect::ProductionWrite;
    cases.push(("mismatched effect", wrong_effect));

    let mut wrong_sandbox = valid.clone();
    wrong_sandbox.idempotency_key = "dispatch-admission-sandbox".into();
    wrong_sandbox.dispatch.as_mut().unwrap().sandbox_profile = SandboxProfile::ReadOnly;
    wrong_sandbox
        .event
        .approval
        .as_mut()
        .unwrap()
        .sandbox_profile = Some(SandboxProfile::ReadOnly);
    wrong_sandbox.response.event = wrong_sandbox.event.clone();
    cases.push(("mismatched sandbox", wrong_sandbox));

    let mut malformed_digest = valid.clone();
    malformed_digest.idempotency_key = "dispatch-admission-digest".into();
    malformed_digest.dispatch.as_mut().unwrap().args_digest = "sha256:not-a-digest".into();
    malformed_digest
        .event
        .approval
        .as_mut()
        .unwrap()
        .arguments_digest = Some("sha256:not-a-digest".into());
    malformed_digest.response.event = malformed_digest.event.clone();
    cases.push(("malformed digest", malformed_digest));

    let mut invalid_tool_name = valid.clone();
    invalid_tool_name.idempotency_key = "dispatch-admission-tool".into();
    invalid_tool_name.dispatch.as_mut().unwrap().tool_name = "Invalid Tool".into();
    invalid_tool_name.event.approval.as_mut().unwrap().tool = "Invalid Tool".into();
    invalid_tool_name.response.event = invalid_tool_name.event.clone();
    cases.push(("invalid tool name", invalid_tool_name));

    let mut oversized_arguments = valid.clone();
    oversized_arguments.idempotency_key = "dispatch-admission-size".into();
    oversized_arguments.dispatch.as_mut().unwrap().args_json =
        json!({"payload": "x".repeat(64 * 1024)});
    cases.push(("oversized arguments", oversized_arguments));

    let mut missing_call = valid.clone();
    missing_call.idempotency_key = "dispatch-admission-missing-call".into();
    missing_call.dispatch.as_mut().unwrap().call_id = "call-missing".into();
    let approval = missing_call.event.approval.as_mut().unwrap();
    approval.call_id = Some("call-missing".into());
    let Some(RunEventData::ApprovalDecided { call_id, .. }) = missing_call.event.data.as_mut()
    else {
        panic!("dispatch fixture has typed approval data");
    };
    *call_id = "call-missing".into();
    missing_call
        .event
        .metadata
        .insert("call_id".into(), json!("call-missing"));
    missing_call.response.event = missing_call.event.clone();
    cases.push(("missing requested call", missing_call));

    for (label, commit) in cases {
        let key = commit.idempotency_key.clone();
        let call_id = commit.dispatch.as_ref().unwrap().call_id.clone();
        assert!(
            matches!(
                store.commit_review(commit).await,
                Err(StorageError::InvalidDispatchTransition(_))
            ),
            "{label} must fail before admission"
        );
        assert_eq!(store.load_run(RUN_ID).await.unwrap(), before, "{label}");
        assert!(
            store.review_receipt(&key).await.unwrap().is_none(),
            "{label}"
        );
        assert!(
            store.dispatch_job(&call_id).await.unwrap().is_none(),
            "{label}"
        );
        assert_eq!(
            finalization_reservation_count(database.path()),
            0,
            "{label}"
        );
    }

    assert_eq!(
        store.commit_review(valid.clone()).await.unwrap(),
        CommitOutcome::Committed
    );
    assert!(matches!(
        store
            .claim_next_dispatch(start_commit(&valid.snapshot))
            .await
            .unwrap(),
        ClaimOutcome::Claimed(_)
    ));
}

#[tokio::test]
async fn database_rejects_dispatch_input_mutation_deletion_and_state_skips() {
    let database = TestDatabase::new();
    let store = seeded_file_store(database.path()).await;
    bootstrap_test_owner(&store).await;
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
    bootstrap_test_owner(&store).await;
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
    bootstrap_test_owner(&store).await;
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
    bootstrap_test_owner(&store).await;
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
async fn dispatch_storage_rejects_noncanonical_event_and_projection_without_partial_writes() {
    let store = seeded_memory_store().await;
    bootstrap_test_owner(&store).await;
    let (snapshot, _) = seed_fixture();
    let review = approved_dispatch_commit(&snapshot, "canonical-dispatch-review");
    store.commit_review(review.clone()).await.unwrap();

    let start = start_commit(&review.snapshot);
    let mut injected_start = start.clone();
    injected_start.event.content = Some("caller-injected content".into());
    assert!(matches!(
        store.claim_next_dispatch(injected_start).await,
        Err(StorageError::InvalidDispatchTransition(_))
    ));
    assert_eq!(
        store
            .dispatch_job("call-local-001")
            .await
            .unwrap()
            .unwrap()
            .status,
        DispatchStatus::Queued
    );
    assert_eq!(store.load_run(RUN_ID).await.unwrap().events.len(), 7);

    store.claim_next_dispatch(start.clone()).await.unwrap();
    let mut injected_completion = completion_commit(&start.snapshot);
    injected_completion.snapshot.metrics[0].value = "x".repeat(8 * 1024);
    assert!(matches!(
        store.complete_dispatch(injected_completion).await,
        Err(StorageError::InvalidDispatchTransition(_))
    ));
    let job = store.dispatch_job("call-local-001").await.unwrap().unwrap();
    assert_eq!(job.status, DispatchStatus::Started);
    assert!(job.result_json.is_none());
    assert_eq!(store.load_run(RUN_ID).await.unwrap().events.len(), 8);
}

#[tokio::test]
async fn queued_job_survives_restart_and_remains_dispatchable() {
    let database = TestDatabase::new();
    let (snapshot, events) = seed_fixture();
    let review = approved_dispatch_commit(&snapshot, "restart-queued");
    {
        let store = SqliteStore::open(database.path()).await.unwrap();
        store.seed_if_empty(snapshot, events).await.unwrap();
        bootstrap_test_owner(&store).await;
        store
            .commit_review_for_actor("user-owner", review.clone())
            .await
            .unwrap();
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
        bootstrap_test_owner(&store).await;
        store
            .commit_review_for_actor("user-owner", review)
            .await
            .unwrap();
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
async fn session_quota_rejects_a_new_key_but_replays_an_admitted_create() {
    let limits = StorageLimits {
        sessions_per_scope: 1,
        sessions_global: 1,
        ..StorageLimits::default()
    };
    let store = SqliteStore::open_with_limits(":memory:", limits)
        .await
        .unwrap();
    bootstrap_test_owner(&store).await;

    let admitted = CreateSessionRequest {
        id: "session-quota-admitted".into(),
        title: "Admitted at the exact Session limit".into(),
    };
    let created = store
        .create_session_for_actor(
            "user-owner",
            admitted.clone(),
            "create-session-quota-admitted",
        )
        .await
        .unwrap();
    assert!(!created.replayed);

    assert!(matches!(
        store
            .create_session_for_actor(
                "user-owner",
                CreateSessionRequest {
                    id: "session-quota-rejected".into(),
                    title: "One Session beyond the limit".into(),
                },
                "create-session-quota-rejected",
            )
            .await,
        Err(StorageError::StorageQuotaExceeded)
    ));

    let replayed = store
        .create_session_for_actor("user-owner", admitted, "create-session-quota-admitted")
        .await
        .unwrap();
    assert!(replayed.replayed);
    assert_eq!(replayed.session, created.session);
    assert_eq!(
        store.list_sessions_for_actor("user-owner").await.unwrap(),
        vec![created.session]
    );
}

#[tokio::test]
async fn session_event_payload_byte_limits_admit_exact_and_reject_plus_one_atomically() {
    let first = CreateSessionRequest {
        id: "session-byte-exact-one".into(),
        title: "Exact byte fixture one".into(),
    };
    let second = CreateSessionRequest {
        id: "session-byte-exact-two".into(),
        title: "Exact byte fixture two".into(),
    };

    let probe_database = TestDatabase::new();
    {
        let probe = SqliteStore::open(probe_database.path()).await.unwrap();
        probe
            .create_session(first.clone(), "probe-byte-one")
            .await
            .unwrap();
        probe
            .create_session(second.clone(), "probe-byte-two")
            .await
            .unwrap();
    }
    let probe = rusqlite::Connection::open(probe_database.path()).unwrap();
    let first_bytes: usize = probe
        .query_row(
            "SELECT event_payload_bytes FROM sessions WHERE id = ?1",
            [&first.id],
            |row| row.get::<_, i64>(0),
        )
        .unwrap()
        .try_into()
        .unwrap();
    let second_bytes: usize = probe
        .query_row(
            "SELECT event_payload_bytes FROM sessions WHERE id = ?1",
            [&second.id],
            |row| row.get::<_, i64>(0),
        )
        .unwrap()
        .try_into()
        .unwrap();
    drop(probe);

    let exact_resource_database = TestDatabase::new();
    let exact_resource = SqliteStore::open_with_limits(
        exact_resource_database.path(),
        StorageLimits {
            session_event_payload_bytes_per_session: first_bytes,
            ..StorageLimits::default()
        },
    )
    .await
    .unwrap();
    exact_resource
        .create_session(first.clone(), "exact-resource-byte-one")
        .await
        .unwrap();
    let exact_counter: i64 = rusqlite::Connection::open(exact_resource_database.path())
        .unwrap()
        .query_row(
            "SELECT event_payload_bytes FROM sessions WHERE id = ?1",
            [&first.id],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(exact_counter, i64::try_from(first_bytes).unwrap());

    let below_resource_database = TestDatabase::new();
    let below_resource = SqliteStore::open_with_limits(
        below_resource_database.path(),
        StorageLimits {
            session_event_payload_bytes_per_session: first_bytes - 1,
            ..StorageLimits::default()
        },
    )
    .await
    .unwrap();
    assert!(matches!(
        below_resource
            .create_session(first.clone(), "below-resource-byte-one")
            .await,
        Err(StorageError::StorageQuotaExceeded)
    ));
    let below_connection = rusqlite::Connection::open(below_resource_database.path()).unwrap();
    assert_eq!(
        below_connection
            .query_row("SELECT COUNT(*) FROM sessions", [], |row| row
                .get::<_, i64>(0))
            .unwrap(),
        0
    );
    assert_eq!(
        below_connection
            .query_row("SELECT COUNT(*) FROM session_command_receipts", [], |row| {
                row.get::<_, i64>(0)
            })
            .unwrap(),
        0,
        "a rejected byte admission must not leave an idempotency receipt"
    );

    let global_exact = first_bytes.checked_add(second_bytes).unwrap();
    let exact_global_database = TestDatabase::new();
    let exact_global = SqliteStore::open_with_limits(
        exact_global_database.path(),
        StorageLimits {
            session_event_payload_bytes_per_session: first_bytes.max(second_bytes),
            run_event_payload_bytes_per_run: 1,
            event_payload_bytes_global: global_exact,
            ..StorageLimits::default()
        },
    )
    .await
    .unwrap();
    exact_global
        .create_session(first.clone(), "exact-global-byte-one")
        .await
        .unwrap();
    exact_global
        .create_session(second.clone(), "exact-global-byte-two")
        .await
        .unwrap();
    let global_counter: i64 = rusqlite::Connection::open(exact_global_database.path())
        .unwrap()
        .query_row(
            "SELECT used_bytes FROM event_payload_usage WHERE singleton = 1",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(global_counter, i64::try_from(global_exact).unwrap());

    let below_global_database = TestDatabase::new();
    let below_global = SqliteStore::open_with_limits(
        below_global_database.path(),
        StorageLimits {
            session_event_payload_bytes_per_session: first_bytes.max(second_bytes),
            run_event_payload_bytes_per_run: 1,
            event_payload_bytes_global: global_exact - 1,
            ..StorageLimits::default()
        },
    )
    .await
    .unwrap();
    below_global
        .create_session(first.clone(), "below-global-byte-one")
        .await
        .unwrap();
    assert!(matches!(
        below_global
            .create_session(second.clone(), "below-global-byte-two")
            .await,
        Err(StorageError::StorageQuotaExceeded)
    ));
    let below_global_connection = rusqlite::Connection::open(below_global_database.path()).unwrap();
    assert_eq!(
        below_global_connection
            .query_row("SELECT COUNT(*) FROM sessions", [], |row| row
                .get::<_, i64>(0))
            .unwrap(),
        1
    );
    assert_eq!(
        below_global_connection
            .query_row(
                "SELECT used_bytes FROM event_payload_usage WHERE singleton = 1",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        i64::try_from(first_bytes).unwrap(),
        "global +1 rejection must roll back its event and counter charge"
    );
}

#[tokio::test]
async fn run_event_payload_byte_limit_admits_exact_and_rejects_plus_one_atomically() {
    let (snapshot, events) = seed_fixture();
    let probe_database = TestDatabase::new();
    let probe_commit = approved_commit(&snapshot, "probe-run-payload-bytes");
    let (baseline_bytes, review_bytes) = {
        let probe = SqliteStore::open(probe_database.path()).await.unwrap();
        assert!(
            probe
                .seed_if_empty(snapshot.clone(), events.clone())
                .await
                .unwrap()
        );
        let connection = rusqlite::Connection::open(probe_database.path()).unwrap();
        let before: i64 = connection
            .query_row(
                "SELECT event_payload_bytes FROM runs WHERE id = ?1",
                [RUN_ID],
                |row| row.get(0),
            )
            .unwrap();
        drop(connection);
        assert_eq!(
            probe.commit_review(probe_commit).await.unwrap(),
            CommitOutcome::Committed
        );
        let after: i64 = rusqlite::Connection::open(probe_database.path())
            .unwrap()
            .query_row(
                "SELECT event_payload_bytes FROM runs WHERE id = ?1",
                [RUN_ID],
                |row| row.get(0),
            )
            .unwrap();
        (before, after - before)
    };
    assert!(baseline_bytes > 0);
    assert!(review_bytes > 0);
    let exact_limit: usize = baseline_bytes
        .checked_add(review_bytes)
        .unwrap()
        .try_into()
        .unwrap();

    let exact_database = TestDatabase::new();
    let exact = SqliteStore::open_with_limits(
        exact_database.path(),
        StorageLimits {
            run_event_payload_bytes_per_run: exact_limit,
            ..StorageLimits::default()
        },
    )
    .await
    .unwrap();
    assert!(
        exact
            .seed_if_empty(snapshot.clone(), events.clone())
            .await
            .unwrap()
    );
    let exact_commit = approved_commit(&snapshot, "exact-run-payload-bytes");
    assert_eq!(
        exact.commit_review(exact_commit.clone()).await.unwrap(),
        CommitOutcome::Committed
    );
    let exact_loaded = exact.load_run(RUN_ID).await.unwrap();
    assert_eq!(exact_loaded.snapshot.run.sequence, 7);
    assert_eq!(exact_loaded.events.len(), 7);
    assert_eq!(exact_loaded.events.last(), Some(&exact_commit.event));
    assert!(
        exact
            .review_receipt("exact-run-payload-bytes")
            .await
            .unwrap()
            .is_some()
    );
    assert_eq!(
        rusqlite::Connection::open(exact_database.path())
            .unwrap()
            .query_row(
                "SELECT event_payload_bytes FROM runs WHERE id = ?1",
                [RUN_ID],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        i64::try_from(exact_limit).unwrap()
    );

    let below_database = TestDatabase::new();
    let below = SqliteStore::open_with_limits(
        below_database.path(),
        StorageLimits {
            run_event_payload_bytes_per_run: exact_limit - 1,
            ..StorageLimits::default()
        },
    )
    .await
    .unwrap();
    assert!(
        below
            .seed_if_empty(snapshot.clone(), events.clone())
            .await
            .unwrap()
    );
    assert!(matches!(
        below
            .commit_review(approved_commit(&snapshot, "below-run-payload-bytes"))
            .await,
        Err(StorageError::StorageQuotaExceeded)
    ));
    let unchanged = below.load_run(RUN_ID).await.unwrap();
    assert_eq!(unchanged.snapshot.run.sequence, 6);
    assert_eq!(unchanged.events.len(), 6);
    assert!(
        below
            .review_receipt("below-run-payload-bytes")
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        rusqlite::Connection::open(below_database.path())
            .unwrap()
            .query_row(
                "SELECT event_payload_bytes FROM runs WHERE id = ?1",
                [RUN_ID],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        baseline_bytes,
        "a rejected review must roll back its event counter charge"
    );
}

#[tokio::test]
async fn open_turn_quota_admits_the_exact_limit_and_rejects_plus_one_atomically() {
    let limits = StorageLimits {
        sessions_per_scope: 3,
        sessions_global: 3,
        open_turns_per_scope: 2,
        open_turns_global: 2,
        ..StorageLimits::default()
    };
    let store = SqliteStore::open_with_limits(":memory:", limits)
        .await
        .unwrap();
    bootstrap_test_owner(&store).await;
    create_owned_test_sessions(
        &store,
        ["session-open-1", "session-open-2", "session-open-3"],
    )
    .await;

    for index in 1..=2 {
        let response = store
            .start_turn_for_actor(
                "user-owner",
                &format!("session-open-{index}"),
                StartTurnRequest {
                    turn_id: format!("turn-open-{index}"),
                    user_message: "Keep this turn open".into(),
                    expected_sequence: 1,
                },
                &format!("start-open-{index}"),
            )
            .await
            .unwrap();
        assert_eq!(response.turn.status, SessionTurnStatus::Open);
    }

    assert!(matches!(
        store
            .start_turn_for_actor(
                "user-owner",
                "session-open-3",
                StartTurnRequest {
                    turn_id: "turn-open-3".into(),
                    user_message: "This is one turn beyond capacity".into(),
                    expected_sequence: 1,
                },
                "start-open-3",
            )
            .await,
        Err(StorageError::StorageQuotaExceeded)
    ));
    let untouched = store.get_session("session-open-3").await.unwrap();
    assert_eq!(untouched.session.status, SessionStatus::Ready);
    assert_eq!(untouched.session.sequence, 1);
    assert!(untouched.turns.is_empty());
}

#[tokio::test]
async fn reply_queue_quota_admits_the_exact_limit_and_rejects_plus_one_atomically() {
    let limits = StorageLimits {
        sessions_per_scope: 3,
        sessions_global: 3,
        open_turns_per_scope: 3,
        open_turns_global: 3,
        active_reply_jobs_per_scope: 2,
        active_reply_jobs_global: 2,
        ..StorageLimits::default()
    };
    let store = SqliteStore::open_with_limits(":memory:", limits)
        .await
        .unwrap();
    bootstrap_test_owner(&store).await;
    create_owned_test_sessions(
        &store,
        ["session-reply-1", "session-reply-2", "session-reply-3"],
    )
    .await;

    for index in 1..=2 {
        let session_id = format!("session-reply-{index}");
        let turn_id = format!("turn-reply-{index}");
        let enqueued = store
            .start_turn_and_enqueue_reply_for_actor(
                "user-owner",
                &session_id,
                StartTurnRequest {
                    turn_id: turn_id.clone(),
                    user_message: "Queue this reply".into(),
                    expected_sequence: 1,
                },
                &format!("start-reply-{index}"),
                reply_job_spec(&format!("reply-quota-{index}"), &turn_id),
            )
            .await
            .unwrap();
        assert_eq!(enqueued.job.status, ReplyJobStatus::Queued);
    }

    assert!(matches!(
        store
            .start_turn_and_enqueue_reply_for_actor(
                "user-owner",
                "session-reply-3",
                StartTurnRequest {
                    turn_id: "turn-reply-3".into(),
                    user_message: "This is one reply beyond capacity".into(),
                    expected_sequence: 1,
                },
                "start-reply-3",
                reply_job_spec("reply-quota-3", "turn-reply-3"),
            )
            .await,
        Err(StorageError::ReplyQueueCapacityExceeded)
    ));
    assert!(store.reply_job("reply-quota-3").await.unwrap().is_none());
    let untouched = store.get_session("session-reply-3").await.unwrap();
    assert_eq!(untouched.session.status, SessionStatus::Ready);
    assert_eq!(untouched.session.sequence, 1);
    assert!(untouched.turns.is_empty());
}

#[tokio::test]
async fn reply_reservations_cover_success_failure_and_missing_claim_fail_closed() {
    let database = TestDatabase::new();
    let store = created_owned_file_session_store(database.path()).await;
    create_owned_test_sessions(&store, ["session-reply-failure", "session-reply-missing"]).await;

    store
        .start_turn_and_enqueue_reply_for_actor(
            "user-owner",
            "session-alpha",
            StartTurnRequest {
                turn_id: "turn-reserved-success".into(),
                user_message: "Complete with two terminal events".into(),
                expected_sequence: 1,
            },
            "start-reserved-success",
            reply_job_spec("reply-reserved-success", "turn-reserved-success"),
        )
        .await
        .unwrap();
    assert_eq!(
        session_finalization_slots(database.path(), "session-alpha", "turn-reserved-success"),
        Some(2)
    );
    let success_reservation = 524_288
        + 12 * i64::try_from("turn-reserved-success".len()).unwrap()
        + 6 * i64::try_from("test-provider".len() + "test-model".len()).unwrap();
    assert_eq!(
        session_finalization_capacity(database.path(), "session-alpha", "turn-reserved-success"),
        Some((2, success_reservation))
    );
    assert!(matches!(
        store.claim_next_reply().await.unwrap(),
        ReplyClaimOutcome::Claimed(_)
    ));
    assert_eq!(
        session_finalization_slots(database.path(), "session-alpha", "turn-reserved-success"),
        Some(2)
    );
    assert_eq!(
        session_finalization_capacity(database.path(), "session-alpha", "turn-reserved-success"),
        Some((2, success_reservation)),
        "claiming a reply must not consume its terminal reservation"
    );
    store
        .complete_reply_success(ReplySuccessCommit {
            job_id: "reply-reserved-success".into(),
            expected_sequence: 2,
            assistant_message: "The reserved reply completed.".into(),
            provenance: AssistantReplyProvenance {
                provider_id: "test-provider".into(),
                model: Some("test-model".into()),
                reply_kind: AssistantReplyKind::Model,
            },
            response_json: model_reply_json("The reserved reply completed."),
        })
        .await
        .unwrap();
    assert_eq!(
        session_finalization_slots(database.path(), "session-alpha", "turn-reserved-success"),
        None
    );

    store
        .start_turn_and_enqueue_reply_for_actor(
            "user-owner",
            "session-reply-failure",
            StartTurnRequest {
                turn_id: "turn-reserved-failure".into(),
                user_message: "Complete with one interruption event".into(),
                expected_sequence: 1,
            },
            "start-reserved-failure",
            reply_job_spec("reply-reserved-failure", "turn-reserved-failure"),
        )
        .await
        .unwrap();
    assert_eq!(
        session_finalization_slots(
            database.path(),
            "session-reply-failure",
            "turn-reserved-failure"
        ),
        Some(2)
    );
    assert!(matches!(
        store.claim_next_reply().await.unwrap(),
        ReplyClaimOutcome::Claimed(_)
    ));
    store
        .complete_reply_failure(ReplyFailureCommit {
            job_id: "reply-reserved-failure".into(),
            expected_sequence: 2,
            error_json: json!({
                "code": "fixture_provider_failure",
                "message": "The fixture reply provider failed",
            }),
        })
        .await
        .unwrap();
    assert_eq!(
        session_finalization_slots(
            database.path(),
            "session-reply-failure",
            "turn-reserved-failure"
        ),
        None
    );

    store
        .start_turn_and_enqueue_reply_for_actor(
            "user-owner",
            "session-reply-missing",
            StartTurnRequest {
                turn_id: "turn-reservation-missing".into(),
                user_message: "Never cross the provider boundary".into(),
                expected_sequence: 1,
            },
            "start-reservation-missing",
            reply_job_spec("reply-reservation-missing", "turn-reservation-missing"),
        )
        .await
        .unwrap();
    remove_session_finalization_reservation(
        database.path(),
        "session-reply-missing",
        "turn-reservation-missing",
    );
    assert!(matches!(
        store.claim_next_reply().await,
        Err(StorageError::FinalizationReservationUnavailable)
    ));
    let still_queued = store
        .reply_job("reply-reservation-missing")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(still_queued.status, ReplyJobStatus::Queued);
    assert_eq!(still_queued.attempt, 0);
}

#[tokio::test]
async fn dispatch_reservation_rolls_back_then_transitions_two_to_one_to_deleted() {
    let database = TestDatabase::new();
    let store = seeded_file_store(database.path()).await;
    bootstrap_test_owner(&store).await;
    let (snapshot, _) = seed_fixture();
    let review = approved_dispatch_commit(&snapshot, "dispatch-reservation-lifecycle");
    store.commit_review(review.clone()).await.unwrap();
    assert_eq!(
        dispatch_finalization_slots(database.path(), RUN_ID, "call-local-001"),
        Some(2)
    );
    assert_eq!(
        dispatch_finalization_capacity(database.path(), RUN_ID, "call-local-001"),
        Some((
            2,
            98_304 + 12 * i64::try_from("call-local-001".len()).unwrap()
        ))
    );

    let start = start_commit(&review.snapshot);
    assert!(matches!(
        store.claim_next_dispatch_with_failure(start.clone()).await,
        Err(StorageError::InjectedFailure)
    ));
    assert_eq!(
        dispatch_finalization_slots(database.path(), RUN_ID, "call-local-001"),
        Some(2)
    );
    assert!(matches!(
        store.claim_next_dispatch(start.clone()).await.unwrap(),
        ClaimOutcome::Claimed(_)
    ));
    assert_eq!(
        dispatch_finalization_slots(database.path(), RUN_ID, "call-local-001"),
        Some(1)
    );
    assert_eq!(
        dispatch_finalization_capacity(database.path(), RUN_ID, "call-local-001"),
        Some((
            1,
            65_536 + 6 * i64::try_from("call-local-001".len()).unwrap()
        ))
    );

    let completion = completion_commit(&start.snapshot);
    assert!(matches!(
        store
            .complete_dispatch_with_failure(completion.clone())
            .await,
        Err(StorageError::InjectedFailure)
    ));
    assert_eq!(
        dispatch_finalization_slots(database.path(), RUN_ID, "call-local-001"),
        Some(1)
    );
    store.complete_dispatch(completion).await.unwrap();
    assert_eq!(
        dispatch_finalization_slots(database.path(), RUN_ID, "call-local-001"),
        None
    );
}

#[tokio::test]
async fn auth_session_capacity_counts_only_active_rows_and_cleans_expired_rows() {
    const FAR_PAST: &str = "2000-01-01T00:00:00.000Z";
    const FAR_FUTURE: &str = "2999-01-01T00:00:00.000Z";

    let database = TestDatabase::new();
    let limits = StorageLimits {
        auth_sessions_per_user: 3,
        auth_sessions_global: 3,
        ..StorageLimits::default()
    };
    let store = SqliteStore::open_with_limits(database.path(), limits)
        .await
        .unwrap();
    store
        .replace_bootstrap_token(&"a".repeat(64), FAR_FUTURE)
        .await
        .unwrap();
    store
        .bootstrap_owner(BootstrapOwnerCommit {
            bootstrap_token_hash: "a".repeat(64),
            user_id: "user-owner".into(),
            username: "owner".into(),
            password_hash: "$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$ZGlnaWVzdA".into(),
            session_token_hash: "b".repeat(64),
            csrf_hash: "c".repeat(64),
            session_expires_at: FAR_FUTURE.into(),
        })
        .await
        .unwrap();
    store
        .create_auth_session(AuthSessionCommit {
            user_id: "user-owner".into(),
            session_token_hash: "d".repeat(64),
            csrf_hash: "e".repeat(64),
            expires_at: FAR_FUTURE.into(),
        })
        .await
        .unwrap();

    let expired_token = "1".repeat(64);
    let connection = rusqlite::Connection::open(database.path()).unwrap();
    connection
        .execute(
            r#"INSERT INTO auth_sessions(
                   token_hash, user_id, csrf_hash, created_at, expires_at, last_seen_at
               ) VALUES (?1, 'user-owner', ?2, ?3, ?3, ?3)"#,
            params![expired_token, "2".repeat(64), FAR_PAST],
        )
        .unwrap();
    drop(connection);
    assert!(store.authenticate(&expired_token).await.unwrap().is_none());

    store
        .create_auth_session(AuthSessionCommit {
            user_id: "user-owner".into(),
            session_token_hash: "3".repeat(64),
            csrf_hash: "4".repeat(64),
            expires_at: FAR_FUTURE.into(),
        })
        .await
        .unwrap();
    assert_eq!(auth_session_count(database.path(), Some(FAR_PAST)), 3);
    assert_eq!(auth_session_count(database.path(), None), 3);

    assert!(matches!(
        store
            .create_auth_session(AuthSessionCommit {
                user_id: "user-owner".into(),
                session_token_hash: "5".repeat(64),
                csrf_hash: "6".repeat(64),
                expires_at: FAR_FUTURE.into(),
            })
            .await,
        Err(StorageError::AuthSessionCapacityExceeded)
    ));
    assert_eq!(auth_session_count(database.path(), Some(FAR_PAST)), 3);
}

#[tokio::test]
async fn v10_event_payload_migration_backfills_utf8_bytes_exactly_and_is_idempotent() {
    let database = TestDatabase::new();
    let session_id = "session-v10-byte-backfill";
    {
        let store = SqliteStore::open(database.path()).await.unwrap();
        store
            .create_session(
                CreateSessionRequest {
                    id: session_id.into(),
                    title: "v10 byte migration fixture".into(),
                },
                "create-v10-byte-backfill",
            )
            .await
            .unwrap();
        let (snapshot, events) = seed_fixture();
        assert!(store.seed_if_empty(snapshot, events).await.unwrap());
    }
    downgrade_event_payload_fixture_to_v10(database.path());

    let session_payload = serde_json::to_string(&json!({
        "ascii": "ASCII-quoted",
        "emoji": "🙂",
        "nul": "\0",
        "quote": "\"double\"",
    }))
    .unwrap();
    let run_payload = serde_json::to_string(&json!({
        "ascii": "run",
        "emoji": "运行🙂",
        "nul": "\0",
        "quote": "'single' and \"double\"",
    }))
    .unwrap();
    let connection = rusqlite::Connection::open(database.path()).unwrap();
    connection
        .execute_batch(
            r#"DROP TRIGGER session_events_reject_update;
               DROP TRIGGER run_events_reject_update;"#,
        )
        .unwrap();
    assert_eq!(
        connection
            .execute(
                "UPDATE session_events SET payload_json = ?1 WHERE session_id = ?2 AND sequence = 1",
                params![&session_payload, session_id],
            )
            .unwrap(),
        1
    );
    assert_eq!(
        connection
            .execute(
                "UPDATE run_events SET payload_json = ?1 WHERE run_id = ?2 AND sequence = 1",
                params![&run_payload, RUN_ID],
            )
            .unwrap(),
        1
    );
    connection
        .execute_batch(
            r#"CREATE TRIGGER session_events_reject_update
               BEFORE UPDATE ON session_events
               BEGIN
                   SELECT RAISE(ABORT, 'session_events are append-only');
               END;
               CREATE TRIGGER run_events_reject_update
               BEFORE UPDATE ON run_events
               BEGIN
                   SELECT RAISE(ABORT, 'run_events are append-only');
               END;"#,
        )
        .unwrap();

    let session_special_bytes: i64 = connection
        .query_row(
            "SELECT length(CAST(?1 AS BLOB))",
            [&session_payload],
            |row| row.get(0),
        )
        .unwrap();
    let run_special_bytes: i64 = connection
        .query_row("SELECT length(CAST(?1 AS BLOB))", [&run_payload], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(
        session_special_bytes,
        i64::try_from(session_payload.len()).unwrap()
    );
    assert_eq!(run_special_bytes, i64::try_from(run_payload.len()).unwrap());
    let expected_session_bytes: i64 = connection
        .query_row(
            r#"SELECT COALESCE(SUM(length(CAST(payload_json AS BLOB))), 0)
               FROM session_events WHERE session_id = ?1"#,
            [session_id],
            |row| row.get(0),
        )
        .unwrap();
    let expected_run_bytes: i64 = connection
        .query_row(
            r#"SELECT COALESCE(SUM(length(CAST(payload_json AS BLOB))), 0)
               FROM run_events WHERE run_id = ?1"#,
            [RUN_ID],
            |row| row.get(0),
        )
        .unwrap();
    let expected_global_bytes: i64 = connection
        .query_row(
            r#"SELECT
                   COALESCE((SELECT SUM(length(CAST(payload_json AS BLOB)))
                             FROM session_events), 0)
                 + COALESCE((SELECT SUM(length(CAST(payload_json AS BLOB)))
                             FROM run_events), 0)"#,
            [],
            |row| row.get(0),
        )
        .unwrap();
    drop(connection);

    {
        let migrated = SqliteStore::open(database.path()).await.unwrap();
        migrated.readiness().await.unwrap();
        let connection = rusqlite::Connection::open(database.path()).unwrap();
        let counters: (i64, i64, i64) = connection
            .query_row(
                r#"SELECT
                       (SELECT event_payload_bytes FROM sessions WHERE id = ?1),
                       (SELECT event_payload_bytes FROM runs WHERE id = ?2),
                       (SELECT used_bytes FROM event_payload_usage WHERE singleton = 1)"#,
                params![session_id, RUN_ID],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(
            counters,
            (
                expected_session_bytes,
                expected_run_bytes,
                expected_global_bytes
            )
        );
    }

    let reopened = SqliteStore::open(database.path()).await.unwrap();
    reopened.readiness().await.unwrap();
    let connection = rusqlite::Connection::open(database.path()).unwrap();
    let versions = connection
        .prepare("SELECT version FROM schema_migrations ORDER BY version")
        .unwrap()
        .query_map([], |row| row.get::<_, i64>(0))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(versions, (1_i64..=11).collect::<Vec<_>>());
    assert_eq!(
        connection
            .query_row(
                "SELECT used_bytes FROM event_payload_usage WHERE singleton = 1",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        expected_global_bytes,
        "reopening v11 must not charge historical payloads a second time"
    );
}

#[tokio::test]
async fn integrity_verification_rejects_parent_global_and_reservation_payload_counter_tampering() {
    let parent_database = TestDatabase::new();
    let parent_store = SqliteStore::open(parent_database.path()).await.unwrap();
    parent_store
        .create_session(
            CreateSessionRequest {
                id: "session-parent-counter-tamper".into(),
                title: "Parent counter tamper".into(),
            },
            "create-parent-counter-tamper",
        )
        .await
        .unwrap();
    let parent_connection = rusqlite::Connection::open(parent_database.path()).unwrap();
    assert_eq!(
        parent_connection
            .execute(
                r#"UPDATE sessions
                   SET event_payload_bytes = event_payload_bytes + 1
                   WHERE id = 'session-parent-counter-tamper'"#,
                [],
            )
            .unwrap(),
        1
    );
    assert!(matches!(
        parent_store.verify_integrity().await,
        Err(StorageError::CorruptData(message))
            if message.contains("event payload byte counters")
    ));

    let global_database = TestDatabase::new();
    let global_store = SqliteStore::open(global_database.path()).await.unwrap();
    global_store
        .create_session(
            CreateSessionRequest {
                id: "session-global-counter-tamper".into(),
                title: "Global counter tamper".into(),
            },
            "create-global-counter-tamper",
        )
        .await
        .unwrap();
    let global_connection = rusqlite::Connection::open(global_database.path()).unwrap();
    assert_eq!(
        global_connection
            .execute(
                "UPDATE event_payload_usage SET used_bytes = used_bytes + 1 WHERE singleton = 1",
                [],
            )
            .unwrap(),
        1
    );
    assert!(matches!(
        global_store.verify_integrity().await,
        Err(StorageError::CorruptData(message))
            if message.contains("event payload byte counters")
    ));

    let reservation_database = TestDatabase::new();
    let reservation_store = created_owned_file_session_store(reservation_database.path()).await;
    reservation_store
        .start_turn_for_actor(
            "user-owner",
            "session-alpha",
            StartTurnRequest {
                turn_id: "turn-reservation-counter-tamper".into(),
                user_message: "Reserve terminal payload capacity".into(),
                expected_sequence: 1,
            },
            "start-reservation-counter-tamper",
        )
        .await
        .unwrap();
    assert_eq!(
        force_finalization_reservation_update(
            reservation_database.path(),
            r#"UPDATE finalization_reservations
               SET remaining_event_slots = 1,
                   remaining_event_payload_bytes = remaining_event_payload_bytes - 1
               WHERE kind = 'session_turn'
                 AND session_id = 'session-alpha'
                 AND turn_id = 'turn-reservation-counter-tamper'"#,
            &[],
        ),
        1
    );
    assert!(matches!(
        reservation_store.verify_integrity().await,
        Err(StorageError::CorruptData(message))
            if message.contains("finalization reservations")
    ));
}

#[tokio::test]
async fn insert_or_replace_cannot_reuse_event_ids_or_change_payload_counters() {
    let database = TestDatabase::new();
    {
        let store = SqliteStore::open(database.path()).await.unwrap();
        store
            .create_session(
                CreateSessionRequest {
                    id: "session-replace-hardening".into(),
                    title: "Replace hardening".into(),
                },
                "create-replace-hardening",
            )
            .await
            .unwrap();
        let (snapshot, events) = seed_fixture();
        assert!(store.seed_if_empty(snapshot, events).await.unwrap());
    }
    let connection = rusqlite::Connection::open(database.path()).unwrap();
    let before: (i64, i64, i64, String, String) = connection
        .query_row(
            r#"SELECT
                   (SELECT event_payload_bytes FROM sessions
                    WHERE id = 'session-replace-hardening'),
                   (SELECT event_payload_bytes FROM runs WHERE id = ?1),
                   (SELECT used_bytes FROM event_payload_usage WHERE singleton = 1),
                   (SELECT payload_json FROM session_events
                    WHERE session_id = 'session-replace-hardening' AND sequence = 1),
                   (SELECT payload_json FROM run_events
                    WHERE run_id = ?1 AND sequence = 1)"#,
            [RUN_ID],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            },
        )
        .unwrap();

    assert!(
        connection
            .execute(
                r#"INSERT OR REPLACE INTO session_events(
                       session_id, sequence, event_id, event_kind, payload_version,
                       payload_json, turn_id, created_at
                   )
                   SELECT session_id, 2, event_id, event_kind, payload_version,
                          payload_json, turn_id, created_at
                   FROM session_events
                   WHERE session_id = 'session-replace-hardening' AND sequence = 1"#,
                [],
            )
            .is_err()
    );
    assert!(
        connection
            .execute(
                r#"INSERT OR REPLACE INTO run_events(
                       run_id, sequence, event_id, event_kind, payload_version, payload_json
                   )
                   SELECT run_id, 7, event_id, event_kind, payload_version, payload_json
                   FROM run_events WHERE run_id = ?1 AND sequence = 1"#,
                [RUN_ID],
            )
            .is_err()
    );

    let after: (i64, i64, i64, i64, i64, String, String) = connection
        .query_row(
            r#"SELECT
                   (SELECT event_payload_bytes FROM sessions
                    WHERE id = 'session-replace-hardening'),
                   (SELECT event_payload_bytes FROM runs WHERE id = ?1),
                   (SELECT used_bytes FROM event_payload_usage WHERE singleton = 1),
                   (SELECT COUNT(*) FROM session_events
                    WHERE session_id = 'session-replace-hardening'),
                   (SELECT COUNT(*) FROM run_events WHERE run_id = ?1),
                   (SELECT payload_json FROM session_events
                    WHERE session_id = 'session-replace-hardening' AND sequence = 1),
                   (SELECT payload_json FROM run_events
                    WHERE run_id = ?1 AND sequence = 1)"#,
            [RUN_ID],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                ))
            },
        )
        .unwrap();
    assert_eq!((after.0, after.1, after.2), (before.0, before.1, before.2));
    assert_eq!((after.3, after.4), (1, 6));
    assert_eq!((after.5, after.6), (before.3, before.4));
}

#[tokio::test]
async fn reply_job_insert_requires_provider_model_payload_reservation() {
    let database = TestDatabase::new();
    let store = created_owned_file_session_store(database.path()).await;
    let turn_id = "turn-provider-budget-hardening";
    store
        .start_turn_for_actor(
            "user-owner",
            "session-alpha",
            StartTurnRequest {
                turn_id: turn_id.into(),
                user_message: "Reserve only a manual turn terminal".into(),
                expected_sequence: 1,
            },
            "start-provider-budget-hardening",
        )
        .await
        .unwrap();
    let reservation_before =
        session_finalization_capacity(database.path(), "session-alpha", turn_id).unwrap();
    assert_eq!(
        reservation_before,
        (2, 524_288 + 12 * i64::try_from(turn_id.len()).unwrap())
    );

    let connection = rusqlite::Connection::open(database.path()).unwrap();
    let inserted = connection.execute(
        r#"INSERT INTO reply_jobs(
               id, actor_user_id, session_id, turn_id, provider_name, model_name,
               status, attempt, request_json, response_json, error_json,
               completion_fingerprint, assistant_event_sequence,
               terminal_event_sequence, queued_at, started_at, finished_at
           ) VALUES (
               'reply-provider-budget-hardening', 'user-owner', 'session-alpha', ?1,
               'test-provider', 'test-model', 'queued', 0, '{}', NULL, NULL,
               NULL, NULL, NULL, ?2, NULL, NULL
           )"#,
        params![turn_id, "2026-08-27T00:00:00.000Z"],
    );
    assert!(inserted.is_err());
    assert_eq!(
        connection
            .query_row(
                "SELECT COUNT(*) FROM reply_jobs WHERE id = 'reply-provider-budget-hardening'",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        0
    );
    assert_eq!(
        session_finalization_capacity(database.path(), "session-alpha", turn_id),
        Some(reservation_before),
        "a rejected reply job must not mutate the manual-turn reservation"
    );
}

#[tokio::test]
async fn claims_fail_closed_on_insufficient_payload_reservations_before_state_transition() {
    let reply_database = TestDatabase::new();
    let reply_store = created_owned_file_session_store(reply_database.path()).await;
    reply_store
        .start_turn_and_enqueue_reply_for_actor(
            "user-owner",
            "session-alpha",
            StartTurnRequest {
                turn_id: "turn-insufficient-payload-reservation".into(),
                user_message: "Do not start this provider request".into(),
                expected_sequence: 1,
            },
            "start-insufficient-payload-reservation",
            reply_job_spec(
                "reply-insufficient-payload-reservation",
                "turn-insufficient-payload-reservation",
            ),
        )
        .await
        .unwrap();
    assert_eq!(
        force_finalization_reservation_update(
            reply_database.path(),
            r#"UPDATE finalization_reservations
               SET remaining_event_slots = 1,
                   remaining_event_payload_bytes = remaining_event_payload_bytes - 1
               WHERE kind = 'session_turn'
                 AND session_id = 'session-alpha'
                 AND turn_id = 'turn-insufficient-payload-reservation'"#,
            &[],
        ),
        1
    );
    assert!(matches!(
        reply_store.claim_next_reply().await,
        Err(StorageError::FinalizationReservationUnavailable)
    ));
    let reply = reply_store
        .reply_job("reply-insufficient-payload-reservation")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(reply.status, ReplyJobStatus::Queued);
    assert_eq!(reply.attempt, 0);
    assert_eq!(
        reply_store
            .get_session("session-alpha")
            .await
            .unwrap()
            .session
            .sequence,
        2
    );

    let dispatch_database = TestDatabase::new();
    let dispatch_store = seeded_file_store(dispatch_database.path()).await;
    bootstrap_test_owner(&dispatch_store).await;
    let (snapshot, _) = seed_fixture();
    let review = approved_dispatch_commit(&snapshot, "dispatch-insufficient-payload-reservation");
    dispatch_store.commit_review(review.clone()).await.unwrap();
    assert_eq!(
        force_finalization_reservation_update(
            dispatch_database.path(),
            r#"UPDATE finalization_reservations
               SET remaining_event_slots = 1,
                   remaining_event_payload_bytes = remaining_event_payload_bytes - 1
               WHERE kind = 'dispatch' AND run_id = ?1 AND call_id = 'call-local-001'"#,
            &[&RUN_ID],
        ),
        1
    );
    assert!(matches!(
        dispatch_store
            .claim_next_dispatch(start_commit(&review.snapshot))
            .await,
        Err(StorageError::FinalizationReservationUnavailable)
    ));
    let dispatch = dispatch_store
        .dispatch_job("call-local-001")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(dispatch.status, DispatchStatus::Queued);
    assert_eq!(
        dispatch_store
            .load_run(RUN_ID)
            .await
            .unwrap()
            .snapshot
            .run
            .sequence,
        7
    );
}

#[tokio::test]
async fn v9_database_over_new_limits_still_opens_reads_and_recovers() {
    let database = TestDatabase::new();
    {
        let store = SqliteStore::open(database.path()).await.unwrap();
        for index in 1..=2 {
            let session_id = format!("session-v9-over-limit-{index}");
            store
                .create_session(
                    CreateSessionRequest {
                        id: session_id.clone(),
                        title: format!("Preexisting Session {index}"),
                    },
                    &format!("create-v9-over-limit-{index}"),
                )
                .await
                .unwrap();
            store
                .start_turn(
                    &session_id,
                    StartTurnRequest {
                        turn_id: format!("turn-v9-over-limit-{index}"),
                        user_message: "This work predates the lower limits".into(),
                        expected_sequence: 1,
                    },
                    &format!("start-v9-over-limit-{index}"),
                )
                .await
                .unwrap();
        }
    }
    downgrade_capacity_fixture_to_v9(database.path());

    let limits = StorageLimits {
        sessions_per_scope: 1,
        sessions_global: 1,
        open_turns_per_scope: 1,
        open_turns_global: 1,
        session_event_payload_bytes_per_session: 1,
        run_event_payload_bytes_per_run: 1,
        event_payload_bytes_global: 1,
        ..StorageLimits::default()
    };
    let reopened = SqliteStore::open_with_limits(database.path(), limits)
        .await
        .unwrap();
    reopened.readiness().await.unwrap();
    assert_eq!(reopened.list_sessions().await.unwrap().len(), 2);
    assert_eq!(finalization_reservation_count(database.path()), 2);

    let recovered = reopened.recover_open_turns().await.unwrap();
    assert_eq!(recovered.len(), 2);
    assert_eq!(finalization_reservation_count(database.path()), 0);
    assert!(reopened.recover_open_turns().await.unwrap().is_empty());
    for index in 1..=2 {
        let detail = reopened
            .get_session(&format!("session-v9-over-limit-{index}"))
            .await
            .unwrap();
        assert_eq!(detail.session.status, SessionStatus::NeedsAttention);
        assert_eq!(detail.session.sequence, 3);
        assert_eq!(detail.turns[0].status, SessionTurnStatus::Interrupted);
    }
}

#[tokio::test]
async fn startup_seeds_enforce_capacity_before_inserting_and_replay_existing_state() {
    let run_limits = StorageLimits {
        run_event_slots_per_run: 5,
        ..StorageLimits::default()
    };
    let run_store = SqliteStore::open_with_limits(":memory:", run_limits)
        .await
        .unwrap();
    let (snapshot, events) = seed_fixture();
    assert!(matches!(
        run_store
            .seed_if_empty(snapshot.clone(), events.clone())
            .await,
        Err(StorageError::StorageQuotaExceeded)
    ));
    assert!(matches!(
        run_store.load_run(RUN_ID).await,
        Err(StorageError::RunNotFound(run_id)) if run_id == RUN_ID
    ));

    let session_limits = StorageLimits {
        session_event_slots_per_session: 1,
        ..StorageLimits::default()
    };
    let session_store = SqliteStore::open_with_limits(":memory:", session_limits)
        .await
        .unwrap();
    assert!(
        session_store
            .seed_if_empty(snapshot.clone(), events.clone())
            .await
            .unwrap()
    );
    assert!(matches!(
        session_store
            .seed_demo_session("session-capacity-seed", "Capacity seed", RUN_ID)
            .await,
        Err(StorageError::StorageQuotaExceeded)
    ));
    assert!(session_store.list_sessions().await.unwrap().is_empty());

    let database = TestDatabase::new();
    {
        let existing = SqliteStore::open(database.path()).await.unwrap();
        assert!(
            existing
                .seed_if_empty(snapshot.clone(), events.clone())
                .await
                .unwrap()
        );
        assert!(
            existing
                .seed_demo_session("session-existing-seed", "Existing seed", RUN_ID)
                .await
                .unwrap()
        );
    }
    let below_existing_state = StorageLimits {
        sessions_per_scope: 1,
        sessions_global: 1,
        session_event_slots_per_session: 1,
        run_event_slots_per_run: 1,
        ..StorageLimits::default()
    };
    let reopened = SqliteStore::open_with_limits(database.path(), below_existing_state)
        .await
        .unwrap();
    assert!(!reopened.seed_if_empty(snapshot, events).await.unwrap());
    assert!(
        !reopened
            .seed_demo_session("session-existing-seed", "Existing seed", RUN_ID)
            .await
            .unwrap()
    );
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

async fn create_owned_test_sessions<const N: usize>(store: &SqliteStore, session_ids: [&str; N]) {
    for session_id in session_ids {
        store
            .create_session_for_actor(
                "user-owner",
                CreateSessionRequest {
                    id: session_id.into(),
                    title: format!("Capacity fixture {session_id}"),
                },
                &format!("create-{session_id}"),
            )
            .await
            .unwrap();
    }
}

fn session_finalization_slots(path: &Path, session_id: &str, turn_id: &str) -> Option<i64> {
    let connection = rusqlite::Connection::open(path).unwrap();
    connection
        .query_row(
            r#"SELECT remaining_event_slots
               FROM finalization_reservations
               WHERE kind = 'session_turn' AND session_id = ?1 AND turn_id = ?2"#,
            params![session_id, turn_id],
            |row| row.get(0),
        )
        .optional()
        .unwrap()
}

fn session_finalization_capacity(
    path: &Path,
    session_id: &str,
    turn_id: &str,
) -> Option<(i64, i64)> {
    let connection = rusqlite::Connection::open(path).unwrap();
    connection
        .query_row(
            r#"SELECT remaining_event_slots, remaining_event_payload_bytes
               FROM finalization_reservations
               WHERE kind = 'session_turn' AND session_id = ?1 AND turn_id = ?2"#,
            params![session_id, turn_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .unwrap()
}

fn dispatch_finalization_slots(path: &Path, run_id: &str, call_id: &str) -> Option<i64> {
    let connection = rusqlite::Connection::open(path).unwrap();
    connection
        .query_row(
            r#"SELECT remaining_event_slots
               FROM finalization_reservations
               WHERE kind = 'dispatch' AND run_id = ?1 AND call_id = ?2"#,
            params![run_id, call_id],
            |row| row.get(0),
        )
        .optional()
        .unwrap()
}

fn dispatch_finalization_capacity(path: &Path, run_id: &str, call_id: &str) -> Option<(i64, i64)> {
    let connection = rusqlite::Connection::open(path).unwrap();
    connection
        .query_row(
            r#"SELECT remaining_event_slots, remaining_event_payload_bytes
               FROM finalization_reservations
               WHERE kind = 'dispatch' AND run_id = ?1 AND call_id = ?2"#,
            params![run_id, call_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .unwrap()
}

fn force_finalization_reservation_update(
    path: &Path,
    statement: &str,
    parameters: &[&dyn rusqlite::ToSql],
) -> usize {
    let connection = rusqlite::Connection::open(path).unwrap();
    let guard_sql: String = connection
        .query_row(
            r#"SELECT sql FROM sqlite_master
               WHERE type = 'trigger'
                 AND name = 'finalization_reservations_enforce_update'"#,
            [],
            |row| row.get(0),
        )
        .unwrap();
    connection
        .execute_batch("DROP TRIGGER finalization_reservations_enforce_update;")
        .unwrap();
    let changed = connection.execute(statement, parameters).unwrap();
    connection.execute_batch(&guard_sql).unwrap();
    changed
}

fn remove_session_finalization_reservation(path: &Path, session_id: &str, turn_id: &str) {
    let changed = force_finalization_reservation_update(
        path,
        r#"UPDATE finalization_reservations
               SET remaining_event_slots = 0,
                   remaining_event_payload_bytes = 0
               WHERE kind = 'session_turn' AND session_id = ?1 AND turn_id = ?2
                 AND remaining_event_slots = 2
                 AND remaining_event_payload_bytes > 0"#,
        &[&session_id, &turn_id],
    );
    assert_eq!(changed, 1);
    let connection = rusqlite::Connection::open(path).unwrap();
    let deleted = connection
        .execute(
            r#"DELETE FROM finalization_reservations
               WHERE kind = 'session_turn' AND session_id = ?1 AND turn_id = ?2
                 AND remaining_event_slots = 0
                 AND remaining_event_payload_bytes = 0"#,
            params![session_id, turn_id],
        )
        .unwrap();
    assert_eq!(deleted, 1);
}

fn auth_session_count(path: &Path, active_after: Option<&str>) -> i64 {
    let connection = rusqlite::Connection::open(path).unwrap();
    match active_after {
        Some(timestamp) => connection
            .query_row(
                "SELECT COUNT(*) FROM auth_sessions WHERE expires_at > ?1",
                [timestamp],
                |row| row.get(0),
            )
            .unwrap(),
        None => connection
            .query_row("SELECT COUNT(*) FROM auth_sessions", [], |row| row.get(0))
            .unwrap(),
    }
}

fn downgrade_capacity_fixture_to_v9(path: &Path) {
    let connection = rusqlite::Connection::open(path).unwrap();
    connection
        .execute_batch(
            r#"DROP TRIGGER session_events_charge_payload_bytes;
               DROP TRIGGER run_events_charge_payload_bytes;
               DROP TRIGGER session_events_require_next_sequence;
               DROP TRIGGER run_events_require_next_sequence;
               DROP TRIGGER reply_jobs_require_session_owner;
               DROP TRIGGER sessions_event_payload_bytes_reject_rollback;
               DROP TRIGGER runs_event_payload_bytes_reject_rollback;
               DROP TRIGGER event_payload_usage_reject_duplicate_insert;
               DROP TRIGGER event_payload_usage_enforce_monotonic_update;
               DROP TRIGGER event_payload_usage_reject_delete;
               DROP TRIGGER finalization_reservations_require_event_payload_capacity_on_insert;
               DROP TRIGGER finalization_reservations_enforce_update;
               DROP TRIGGER finalization_reservations_reject_live_delete;
               DROP TABLE event_payload_usage;
               ALTER TABLE sessions DROP COLUMN event_payload_bytes;
               ALTER TABLE runs DROP COLUMN event_payload_bytes;
               DROP TABLE finalization_reservations;
               DROP INDEX auth_sessions_expiry_idx;

               CREATE TRIGGER session_events_require_next_sequence
               BEFORE INSERT ON session_events
               WHEN NEW.sequence <> (
                   SELECT sequence + 1 FROM sessions WHERE id = NEW.session_id
               )
               BEGIN
                   SELECT RAISE(ABORT, 'session event sequence must be contiguous');
               END;

               CREATE TRIGGER run_events_require_next_sequence
               BEFORE INSERT ON run_events
               WHEN NEW.sequence <> COALESCE((
                   SELECT MAX(sequence) + 1
                   FROM run_events
                   WHERE run_id = NEW.run_id
               ), 1)
               BEGIN
                   SELECT RAISE(ABORT, 'run event sequence must be contiguous');
               END;

               CREATE TRIGGER reply_jobs_require_session_owner
               BEFORE INSERT ON reply_jobs
               WHEN NEW.actor_user_id
                    IS NOT (SELECT owner_user_id FROM sessions WHERE id = NEW.session_id)
               BEGIN
                   SELECT RAISE(ABORT, 'reply actor must own the session');
               END;

               DELETE FROM schema_migrations WHERE version >= 10;"#,
        )
        .unwrap();
    let version: i64 = connection
        .query_row("SELECT MAX(version) FROM schema_migrations", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(version, 9);
}

fn downgrade_event_payload_fixture_to_v10(path: &Path) {
    let connection = rusqlite::Connection::open(path).unwrap();
    connection
        .execute_batch(
            r#"DROP TRIGGER session_events_charge_payload_bytes;
               DROP TRIGGER run_events_charge_payload_bytes;
               DROP TRIGGER session_events_require_next_sequence;
               DROP TRIGGER run_events_require_next_sequence;
               DROP TRIGGER reply_jobs_require_session_owner;
               DROP TRIGGER sessions_event_payload_bytes_reject_rollback;
               DROP TRIGGER runs_event_payload_bytes_reject_rollback;
               DROP TRIGGER event_payload_usage_reject_duplicate_insert;
               DROP TRIGGER event_payload_usage_enforce_monotonic_update;
               DROP TRIGGER event_payload_usage_reject_delete;
               DROP TRIGGER finalization_reservations_require_event_payload_capacity_on_insert;
               DROP TRIGGER finalization_reservations_enforce_update;
               DROP TRIGGER finalization_reservations_reject_live_delete;
               DROP TABLE event_payload_usage;
               ALTER TABLE sessions DROP COLUMN event_payload_bytes;
               ALTER TABLE runs DROP COLUMN event_payload_bytes;
               ALTER TABLE finalization_reservations
                   DROP COLUMN remaining_event_payload_bytes;

               CREATE TRIGGER session_events_require_next_sequence
               BEFORE INSERT ON session_events
               WHEN NEW.sequence <> (
                   SELECT sequence + 1 FROM sessions WHERE id = NEW.session_id
               )
               BEGIN
                   SELECT RAISE(ABORT, 'session event sequence must be contiguous');
               END;

               CREATE TRIGGER run_events_require_next_sequence
               BEFORE INSERT ON run_events
               WHEN NEW.sequence <> COALESCE((
                   SELECT MAX(sequence) + 1
                   FROM run_events
                   WHERE run_id = NEW.run_id
               ), 1)
               BEGIN
                   SELECT RAISE(ABORT, 'run event sequence must be contiguous');
               END;

               CREATE TRIGGER reply_jobs_require_session_owner
               BEFORE INSERT ON reply_jobs
               WHEN NEW.actor_user_id
                    IS NOT (SELECT owner_user_id FROM sessions WHERE id = NEW.session_id)
               BEGIN
                   SELECT RAISE(ABORT, 'reply actor must own the session');
               END;

               CREATE TRIGGER finalization_reservations_enforce_update
               BEFORE UPDATE ON finalization_reservations
               WHEN NOT (
                   NEW.kind IS OLD.kind
                   AND NEW.session_id IS OLD.session_id
                   AND NEW.turn_id IS OLD.turn_id
                   AND NEW.run_id IS OLD.run_id
                   AND NEW.call_id IS OLD.call_id
                   AND NEW.reserved_bytes IS OLD.reserved_bytes
                   AND NEW.created_at IS OLD.created_at
                   AND (
                       (NEW.scope_id IS OLD.scope_id
                           AND NEW.remaining_event_slots >= 0
                           AND NEW.remaining_event_slots < OLD.remaining_event_slots)
                       OR
                       (OLD.scope_id = '__legacy__'
                           AND NEW.scope_id <> '__legacy__'
                           AND NEW.remaining_event_slots = OLD.remaining_event_slots)
                   )
               )
               BEGIN
                   SELECT RAISE(ABORT, 'reservation updates must consume slots or claim legacy scope');
               END;

               CREATE TRIGGER finalization_reservations_reject_live_delete
               BEFORE DELETE ON finalization_reservations
               WHEN OLD.remaining_event_slots <> 0
               BEGIN
                   SELECT RAISE(ABORT, 'reservation must be empty before deletion');
               END;

               DELETE FROM schema_migrations WHERE version = 11;"#,
        )
        .unwrap();
    let version: i64 = connection
        .query_row("SELECT MAX(version) FROM schema_migrations", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(version, 10);
}

fn finalization_reservation_count(path: &Path) -> i64 {
    rusqlite::Connection::open(path)
        .unwrap()
        .query_row(
            "SELECT COUNT(*) FROM finalization_reservations",
            [],
            |row| row.get(0),
        )
        .unwrap()
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

async fn bootstrap_test_owner(store: &SqliteStore) {
    let expiry = (chrono::Utc::now() + chrono::Duration::hours(1))
        .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    store
        .replace_bootstrap_token(&"a".repeat(64), &expiry)
        .await
        .unwrap();
    store
        .bootstrap_owner(BootstrapOwnerCommit {
            bootstrap_token_hash: "a".repeat(64),
            user_id: "user-owner".into(),
            username: "owner".into(),
            password_hash: "$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$ZGlnaWVzdA".into(),
            session_token_hash: "b".repeat(64),
            csrf_hash: "c".repeat(64),
            session_expires_at: expiry,
        })
        .await
        .unwrap();
}

fn set_test_user_status(path: &Path, user_id: &str, status: &str) {
    let connection = rusqlite::Connection::open(path).unwrap();
    connection
        .execute(
            "UPDATE users SET status = ?1, updated_at = ?2 WHERE id = ?3",
            params![status, "2026-08-27T00:00:00.000Z", user_id],
        )
        .unwrap();
}

fn set_test_user_role(path: &Path, user_id: &str, role: &str) {
    let connection = rusqlite::Connection::open(path).unwrap();
    connection
        .execute(
            "UPDATE users SET role = ?1, updated_at = ?2 WHERE id = ?3",
            params![role, "2026-08-27T00:00:00.000Z", user_id],
        )
        .unwrap();
}

fn insert_test_member(path: &Path, user_id: &str, username: &str) {
    let connection = rusqlite::Connection::open(path).unwrap();
    connection
        .pragma_update(None, "foreign_keys", true)
        .unwrap();
    connection
        .execute(
            r#"INSERT INTO users(
                   id, username, role, status, password_hash, created_at, updated_at
               ) VALUES (?1, ?2, 'member', 'active', ?3, ?4, ?4)"#,
            params![
                user_id,
                username,
                "$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$ZGlnaWVzdA",
                "2026-08-27T00:00:00.000Z",
            ],
        )
        .unwrap();
}

fn insert_legacy_oversized_reply_fixture(
    path: &Path,
    session_id: &str,
    turn_id: &str,
    user_message: &str,
    job_id: &str,
) {
    let connection = rusqlite::Connection::open(path).unwrap();
    connection
        .pragma_update(None, "foreign_keys", true)
        .unwrap();
    let timestamp = "2026-08-27T00:00:00.000Z";
    let title = "Legacy oversized Session";
    let finalization_payload_bytes = 524_288_i64
        + 12 * i64::try_from(turn_id.len()).unwrap()
        + 6 * i64::try_from("test-provider".len() + "test-model".len()).unwrap();
    connection
        .execute(
            r#"INSERT INTO sessions(
                   id, title, status, created_at, updated_at, sequence,
                   projection_sequence, active_turn_id, owner_user_id
               ) VALUES (?1, ?2, 'ready', ?3, ?3, 0, 0, NULL, 'user-owner')"#,
            params![session_id, title, timestamp],
        )
        .unwrap();

    let created = SessionEvent {
        sequence: 1,
        id: format!("{session_id}:event:1"),
        at: timestamp.into(),
        data: SessionEventData::SessionCreated {
            title: title.into(),
        },
    };
    connection
        .execute(
            r#"INSERT INTO session_events(
                   session_id, sequence, event_id, event_kind, payload_version,
                   payload_json, turn_id, created_at
               ) VALUES (?1, 1, ?2, 'session_created', 1, ?3, NULL, ?4)"#,
            params![
                session_id,
                created.id,
                serde_json::to_string(&created).unwrap(),
                timestamp,
            ],
        )
        .unwrap();
    connection
        .execute(
            r#"UPDATE sessions
               SET sequence = 1, projection_sequence = 1
               WHERE id = ?1"#,
            [session_id],
        )
        .unwrap();

    connection
        .execute(
            r#"INSERT INTO session_turns(
                   id, session_id, ordinal, status, user_message, assistant_message,
                   started_at, completed_at
               ) VALUES (?1, ?2, 1, 'open', ?3, NULL, ?4, NULL)"#,
            params![turn_id, session_id, user_message, timestamp],
        )
        .unwrap();
    let user_event = SessionEvent {
        sequence: 2,
        id: format!("{session_id}:event:2"),
        at: timestamp.into(),
        data: SessionEventData::UserMessage {
            turn_id: turn_id.into(),
            content: user_message.into(),
        },
    };
    connection
        .execute(
            r#"INSERT INTO session_events(
                   session_id, sequence, event_id, event_kind, payload_version,
                   payload_json, turn_id, created_at
               ) VALUES (?1, 2, ?2, 'user_message', 1, ?3, ?4, ?5)"#,
            params![
                session_id,
                user_event.id,
                serde_json::to_string(&user_event).unwrap(),
                turn_id,
                timestamp,
            ],
        )
        .unwrap();
    connection
        .execute(
            r#"UPDATE sessions
               SET status = 'running', active_turn_id = ?1,
                   sequence = 2, projection_sequence = 2, updated_at = ?2
               WHERE id = ?3"#,
            params![turn_id, timestamp, session_id],
        )
        .unwrap();

    connection
        .execute(
            r#"INSERT INTO finalization_reservations(
                   kind, scope_id, session_id, turn_id, run_id, call_id,
                   remaining_event_slots, remaining_event_payload_bytes,
                   reserved_bytes, created_at
               ) VALUES (
                   'session_turn', 'user-owner', ?1, ?2, NULL, NULL,
                   2, ?3, NULL, ?4
               )"#,
            params![session_id, turn_id, finalization_payload_bytes, timestamp],
        )
        .unwrap();
    connection
        .execute(
            r#"INSERT INTO reply_jobs(
                   id, actor_user_id, session_id, turn_id, provider_name, model_name,
                   status, attempt, request_json, response_json, error_json,
                   completion_fingerprint, assistant_event_sequence,
                   terminal_event_sequence, queued_at, started_at, finished_at
               ) VALUES (
                   ?1, 'user-owner', ?2, ?3, 'test-provider', 'test-model',
                   'queued', 0, ?4, NULL, NULL, NULL, NULL, NULL, ?5, NULL, NULL
               )"#,
            params![
                job_id,
                session_id,
                turn_id,
                serde_json::to_string(&json!({
                    "messages": [{"role": "user", "content": user_message}],
                }))
                .unwrap(),
                timestamp,
            ],
        )
        .unwrap();
}

async fn created_owned_session_store() -> SqliteStore {
    let store = created_session_store().await;
    bootstrap_test_owner(&store).await;
    store
}

async fn created_owned_file_session_store(path: &Path) -> SqliteStore {
    let store = SqliteStore::open(path).await.unwrap();
    store
        .create_session(alpha_session_request(), "create-session-alpha")
        .await
        .unwrap();
    bootstrap_test_owner(&store).await;
    store
}

fn reply_job_spec(id: &str, turn_id: &str) -> ReplyJobSpec {
    ReplyJobSpec {
        id: id.into(),
        actor_user_id: "user-owner".into(),
        provider_name: "test-provider".into(),
        model_name: Some("test-model".into()),
        request_json: json!({
            "messages": [{"role": "user", "content": format!("reply to {turn_id}")}]
        }),
    }
}

fn model_reply_json(content: &str) -> Value {
    json!({
        "content": content,
        "finish_reason": "stop",
        "provider": {
            "provider_id": "test-provider",
            "model": "test-model",
            "reply_kind": "model",
        },
    })
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

async fn seeded_store() -> SqliteStore {
    let store = SqliteStore::open(":memory:").await.unwrap();
    let (snapshot, events) = seed_fixture();
    assert!(store.seed_if_empty(snapshot, events).await.unwrap());
    store
}

async fn bounded_event_store(count: usize) -> SqliteStore {
    let store = SqliteStore::open(":memory:").await.unwrap();
    seed_event_count(&store, count).await;
    bootstrap_test_owner(&store).await;
    store
}

async fn seed_event_count(store: &SqliteStore, count: usize) {
    let (mut snapshot, _) = seed_fixture();
    let events = (1..=count)
        .map(|sequence| event(sequence as u64, EventType::Step, "bounded page event"))
        .collect::<Vec<_>>();
    snapshot.run.sequence = count as u64;
    snapshot.run.status = RunStatus::Active;
    assert!(store.seed_if_empty(snapshot, events).await.unwrap());
}

fn seed_fixture() -> (RunSnapshot, Vec<RunEvent>) {
    let mut events = vec![
        event(1, EventType::User, "User report received"),
        event(2, EventType::Reasoning, "Hypothesis formed"),
        event(3, EventType::Step, "Diagnostics selected"),
        event(4, EventType::ToolCall, "Telemetry collected"),
        event(5, EventType::Evidence, "Pressure correlated"),
    ];
    events[3].data = Some(RunEventData::ToolCallRequested {
        call: dispatch_fixture_call(),
        status: ToolCallStatus::Requested,
    });
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

fn point_context_fixture() -> (RunSnapshot, Vec<RunEvent>) {
    let (snapshot, mut events) = seed_fixture();
    let call = dispatch_fixture_call();
    let approval = events[5]
        .approval
        .as_mut()
        .expect("fixture has a pending approval");
    approval.tool = call.tool.clone();
    approval.call_id = Some(call.call_id.clone());
    approval.policy_revision = Some("rev-2026-08-26".into());
    approval.arguments_digest = Some(call.arguments_digest.clone());
    approval.sandbox_profile = Some(call.sandbox_profile.clone());
    approval.scope = Some(ApprovalScope::AllowOnce);
    events[5].data = Some(RunEventData::ApprovalRequested {
        approval_id: approval.id.clone(),
        call_id: call.call_id,
        scope: ApprovalScope::AllowOnce,
        status: ToolCallStatus::WaitingForApproval,
    });
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

fn dispatch_fixture_call() -> ToolCall {
    ToolCall {
        call_id: "call-local-001".into(),
        tool: "local.echo".into(),
        tool_version: "1.0.0".into(),
        arguments: json!({"message": "raise the local fixture ceiling"}),
        arguments_digest: format!("sha256:{}", "a".repeat(64)),
        effect: ToolEffect::LocalWrite,
        sandbox_profile: SandboxProfile::WorkspaceWrite,
        executor_status: ToolExecutorStatus::Available,
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
        approving_actor_user_id: "user-owner".into(),
        tool_name: "local.echo".into(),
        tool_version: "1.0.0".into(),
        effect: ToolEffect::LocalWrite,
        args_json: json!({"message": "raise the local fixture ceiling"}),
        args_digest: format!("sha256:{}", "a".repeat(64)),
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
    let call = dispatch_fixture_call();
    let approval = Approval {
        id: "APR-901".into(),
        status: ApprovalStatus::Approved,
        action: "update connection ceiling".into(),
        tool: call.tool.clone(),
        change: "connections: 80 -> 120".into(),
        requires_approval: true,
        call_id: Some(call.call_id.clone()),
        policy_revision: Some("rev-2026-08-26".into()),
        arguments_digest: Some(call.arguments_digest.clone()),
        sandbox_profile: Some(call.sandbox_profile.clone()),
        scope: Some(ApprovalScope::AllowOnce),
    };
    let transition = kernel::start_tool_dispatch(
        &queued.run,
        &approval,
        &call,
        "local-dev",
        queued.run.sequence + 1,
        "2026-08-26T01:20:01Z",
    )
    .unwrap();
    assert_eq!(transition.run.status, RunStatus::Running);
    assert_eq!(transition.event.step, 4);
    assert_eq!(transition.event.title, "Tool dispatch checkpoint recorded");
    assert_eq!(
        transition.event.summary.as_deref(),
        Some("The durable dispatch checkpoint was recorded. A tool result is still required.")
    );
    assert_eq!(
        transition.event.metadata,
        BTreeMap::from([
            ("durable".into(), json!(true)),
            ("side_effect_claimed".into(), json!(false)),
        ])
    );
    assert_eq!(
        transition.event.data,
        Some(RunEventData::ToolDispatchStarted {
            call_id: "call-local-001".into(),
            executor: "local-dev".into(),
            executor_status: ToolExecutorStatus::Available,
            sandbox_profile: SandboxProfile::WorkspaceWrite,
            status: ToolCallStatus::Running,
        })
    );
    let mut snapshot = queued.clone();
    snapshot.run = transition.run;
    DispatchStartCommit {
        call_id: "call-local-001".into(),
        expected_sequence: queued.run.sequence,
        snapshot,
        event: transition.event,
    }
}

fn completion_commit(running: &RunSnapshot) -> DispatchCompleteCommit {
    let outcome = ToolOutcome::Succeeded {
        summary: "Local fixture updated".into(),
        output_digest: Some("sha256:output-local-001".into()),
    };
    let transition = kernel::apply_tool_result(
        &running.run,
        &dispatch_fixture_call(),
        outcome.clone(),
        running.run.sequence + 1,
        "2026-08-26T01:20:02Z",
    )
    .unwrap();
    assert_eq!(transition.run.status, RunStatus::Succeeded);
    assert_eq!(transition.event.step, 4);
    assert_eq!(transition.event.title, "Tool execution succeeded");
    assert_eq!(
        transition.event.metadata,
        BTreeMap::from([
            ("durable".into(), json!(true)),
            ("outcome_known".into(), json!(true)),
        ])
    );
    assert_eq!(
        transition.event.data,
        Some(RunEventData::ToolResult {
            call_id: "call-local-001".into(),
            outcome: outcome.clone(),
            status: ToolCallStatus::Succeeded,
        })
    );
    let mut snapshot = running.clone();
    snapshot.run = transition.run;
    DispatchCompleteCommit {
        call_id: "call-local-001".into(),
        expected_sequence: running.run.sequence,
        snapshot,
        event: transition.event,
        result_json: serde_json::to_value(outcome).unwrap(),
    }
}

fn recovery_commit(running: &RunSnapshot) -> DispatchRecoveryCommit {
    let outcome = ToolOutcome::OutcomeUnknown {
        summary: "Process stopped after dispatch start; the side effect is unknown.".into(),
    };
    let transition = kernel::apply_tool_result(
        &running.run,
        &dispatch_fixture_call(),
        outcome.clone(),
        running.run.sequence + 1,
        "2026-08-26T01:21:00Z",
    )
    .unwrap();
    assert_eq!(transition.run.status, RunStatus::NeedsAttention);
    assert_eq!(transition.event.step, 4);
    assert_eq!(transition.event.title, "Tool outcome is unknown");
    assert_eq!(
        transition.event.metadata,
        BTreeMap::from([
            ("durable".into(), json!(true)),
            ("outcome_known".into(), json!(false)),
        ])
    );
    assert_eq!(
        transition.event.data,
        Some(RunEventData::ToolResult {
            call_id: "call-local-001".into(),
            outcome: outcome.clone(),
            status: ToolCallStatus::OutcomeUnknown,
        })
    );
    let mut snapshot = running.clone();
    snapshot.run = transition.run;
    DispatchRecoveryCommit {
        call_id: "call-local-001".into(),
        expected_sequence: running.run.sequence,
        snapshot,
        event: transition.event,
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
    for mut event in events {
        // Schema v1 predates typed RunEventData.
        event.data = None;
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

fn create_v7_database_with_legacy_dispatch(path: &Path) {
    create_v1_database(path);
    let connection = rusqlite::Connection::open(path).unwrap();
    connection
        .pragma_update(None, "foreign_keys", true)
        .unwrap();
    for (version, migration) in [
        (2_i64, include_str!("../migrations/0002_tool_execution.sql")),
        (
            3_i64,
            include_str!("../migrations/0003_runtime_identity.sql"),
        ),
        (4_i64, include_str!("../migrations/0004_sessions.sql")),
        (5_i64, include_str!("../migrations/0005_accounts.sql")),
        (6_i64, include_str!("../migrations/0006_actor_receipts.sql")),
        (7_i64, include_str!("../migrations/0007_reply_jobs.sql")),
    ] {
        connection.execute_batch(migration).unwrap();
        connection
            .execute(
                "INSERT INTO schema_migrations(version, applied_at) VALUES (?1, ?2)",
                params![version, format!("2026-08-26T00:00:0{version}.000Z")],
            )
            .unwrap();
    }
    let call = ToolCall {
        call_id: "call-v7-legacy".into(),
        tool: "local.echo".into(),
        tool_version: "1.0.0".into(),
        arguments: json!({}),
        arguments_digest: "sha256:args-v7".into(),
        effect: ToolEffect::LocalWrite,
        sandbox_profile: SandboxProfile::WorkspaceWrite,
        executor_status: ToolExecutorStatus::Available,
    };
    let mut requested = event(4, EventType::ToolCall, "Legacy tool call requested");
    requested.data = Some(RunEventData::ToolCallRequested {
        call: call.clone(),
        status: ToolCallStatus::Requested,
    });
    let mut approved = event(6, EventType::Approval, "Legacy tool call approved");
    approved.approval = Some(Approval {
        id: "APR-V7".into(),
        status: ApprovalStatus::Approved,
        action: "run legacy local echo".into(),
        tool: call.tool.clone(),
        change: "record the legacy dispatch".into(),
        requires_approval: true,
        call_id: Some(call.call_id.clone()),
        policy_revision: Some("rev-v7".into()),
        arguments_digest: Some(call.arguments_digest.clone()),
        sandbox_profile: Some(call.sandbox_profile.clone()),
        scope: Some(ApprovalScope::AllowOnce),
    });
    approved.data = Some(RunEventData::ApprovalDecided {
        approval_id: "APR-V7".into(),
        call_id: call.call_id.clone(),
        decision: ReviewDecision::Approve,
        status: ToolCallStatus::Queued,
    });
    connection
        .execute_batch("DROP TRIGGER run_events_reject_update;")
        .unwrap();
    connection
        .execute(
            r#"UPDATE run_events
               SET event_kind = 'tool_call', payload_version = 2, payload_json = ?1
               WHERE run_id = ?2 AND sequence = 4"#,
            params![serde_json::to_string(&requested).unwrap(), RUN_ID],
        )
        .unwrap();
    connection
        .execute(
            r#"UPDATE run_events
               SET event_kind = 'approval', payload_version = 2, payload_json = ?1
               WHERE run_id = ?2 AND sequence = 6"#,
            params![serde_json::to_string(&approved).unwrap(), RUN_ID],
        )
        .unwrap();
    connection
        .execute_batch(
            r#"CREATE TRIGGER run_events_reject_update
               BEFORE UPDATE ON run_events
               BEGIN
                   SELECT RAISE(ABORT, 'run_events are append-only');
               END;"#,
        )
        .unwrap();
    connection
        .execute(
            "UPDATE runs SET status = 'active', execution_status = 'queued' WHERE id = ?1",
            [RUN_ID],
        )
        .unwrap();
    connection
        .execute(
            r#"INSERT INTO dispatch_jobs(
                   call_id, run_id, approval_id, approval_event_sequence,
                   tool_name, tool_version, effect, args_json, args_digest,
                   policy_id, policy_revision, sandbox_profile, status, attempt,
                   result_json, queued_at, started_at, finished_at,
                   start_event_sequence, result_event_sequence
               ) VALUES (
                   'call-v7-legacy', ?1, 'APR-V7', 6,
                   'local.echo', '1.0.0', 'local_write', '{}',
                   'sha256:args-v7', 'local-alpha', 'rev-v7', 'workspace_write',
                   'queued', 0, NULL, '2026-08-26T01:20:00.000Z',
                   NULL, NULL, NULL, NULL
               )"#,
            [RUN_ID],
        )
        .unwrap();
}

fn create_v8_database_with_legacy_dispatch(path: &Path) {
    create_v7_database_with_legacy_dispatch(path);
    let connection = rusqlite::Connection::open(path).unwrap();
    connection
        .pragma_update(None, "foreign_keys", true)
        .unwrap();
    connection
        .execute_batch(include_str!("../migrations/0008_actor_boundaries.sql"))
        .unwrap();
    connection
        .execute(
            "INSERT INTO schema_migrations(version, applied_at) VALUES (8, ?1)",
            ["2026-08-26T00:00:08.000Z"],
        )
        .unwrap();
}

fn create_v8_database_with_oversized_point_fixture(
    path: &Path,
    run_id: &str,
    pending_call_id: &str,
    pending_approval_id: &str,
    dispatch_call_id: &str,
    dispatch_approval_id: &str,
) {
    create_v8_database_with_legacy_dispatch(path);
    let connection = rusqlite::Connection::open(path).unwrap();
    connection
        .pragma_update(None, "foreign_keys", true)
        .unwrap();
    let timestamp = "2026-08-26T03:00:00.000Z";
    connection
        .execute(
            r#"INSERT INTO users(
                   id, username, role, status, password_hash, created_at, updated_at
               ) VALUES ('user-v8-owner', 'v8-owner', 'owner', 'active',
                         '$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$ZGlnaWVzdA', ?1, ?1)"#,
            [timestamp],
        )
        .unwrap();
    connection
        .execute(
            r#"INSERT INTO user_preferences(user_id, theme, revision, updated_at)
               VALUES ('user-v8-owner', 'system', 1, ?1)"#,
            [timestamp],
        )
        .unwrap();
    connection
        .execute(
            "UPDATE sessions SET owner_user_id = 'user-v8-owner' WHERE owner_user_id IS NULL",
            [],
        )
        .unwrap();
    connection
        .execute(
            "UPDATE runs SET owner_user_id = 'user-v8-owner' WHERE owner_user_id IS NULL",
            [],
        )
        .unwrap();
    connection
        .execute(
            r#"UPDATE dispatch_jobs SET approving_actor_user_id = 'user-v8-owner'
               WHERE approving_actor_user_id IS NULL"#,
            [],
        )
        .unwrap();
    connection
        .execute(
            r#"UPDATE session_command_receipts SET actor_scope = 'user-v8-owner'
               WHERE actor_scope = '__legacy__'"#,
            [],
        )
        .unwrap();
    connection
        .execute(
            r#"UPDATE idempotency_receipts SET actor_scope = 'user-v8-owner'
               WHERE actor_scope = '__legacy__'"#,
            [],
        )
        .unwrap();
    connection
        .execute(
            r#"INSERT INTO incidents(
                   id, title, severity, status, service, region, user_impact, since
               ) VALUES ('INC-V8-POINT', 'V8 point lookup fixture', 'low', 'investigating',
                         'local-fixture', 'local', 'none', ?1)"#,
            [timestamp],
        )
        .unwrap();
    connection
        .execute(
            r#"INSERT INTO runs(
                   id, incident_id, status, environment, started_at, duration_seconds,
                   agent, sequence, projection_sequence, metrics_json, evidence_json,
                   tool_policy_json, execution_status, owner_user_id
               ) VALUES (?1, 'INC-V8-POINT', 'active', 'local', ?2, 0,
                         'Zeus Migration Test', 4, 4, '[]', '[]', NULL,
                         'queued', 'user-v8-owner')"#,
            params![run_id, timestamp],
        )
        .unwrap();

    let pending_call = ToolCall {
        call_id: pending_call_id.into(),
        tool: "local.pending".into(),
        tool_version: "1.0.0".into(),
        arguments: json!({"kind": "pending-v8"}),
        arguments_digest: "sha256:v8-pending".into(),
        effect: ToolEffect::LocalWrite,
        sandbox_profile: SandboxProfile::WorkspaceWrite,
        executor_status: ToolExecutorStatus::Available,
    };
    let dispatch_call = ToolCall {
        call_id: dispatch_call_id.into(),
        tool: "local.dispatch".into(),
        tool_version: "1.0.0".into(),
        arguments: json!({"kind": "dispatch-v8"}),
        arguments_digest: "sha256:v8-dispatch".into(),
        effect: ToolEffect::LocalWrite,
        sandbox_profile: SandboxProfile::WorkspaceWrite,
        executor_status: ToolExecutorStatus::Available,
    };

    let mut pending_request = event(1, EventType::ToolCall, "V8 pending call requested");
    pending_request.id = "evt-v8-point-001".into();
    pending_request.data = Some(RunEventData::ToolCallRequested {
        call: pending_call.clone(),
        status: ToolCallStatus::Requested,
    });
    let mut pending_approval = event(2, EventType::Approval, "V8 approval requested");
    pending_approval.id = "evt-v8-point-002".into();
    pending_approval.approval = Some(Approval {
        id: pending_approval_id.into(),
        status: ApprovalStatus::Pending,
        action: "allow pending v8 call".into(),
        tool: pending_call.tool.clone(),
        change: "exercise migrated review lookup".into(),
        requires_approval: true,
        call_id: Some(pending_call.call_id.clone()),
        policy_revision: Some("rev-v8-point".into()),
        arguments_digest: Some(pending_call.arguments_digest.clone()),
        sandbox_profile: Some(pending_call.sandbox_profile.clone()),
        scope: Some(ApprovalScope::AllowOnce),
    });
    pending_approval.data = Some(RunEventData::ApprovalRequested {
        approval_id: pending_approval_id.into(),
        call_id: pending_call.call_id.clone(),
        scope: ApprovalScope::AllowOnce,
        status: ToolCallStatus::WaitingForApproval,
    });
    let mut dispatch_request = event(3, EventType::ToolCall, "V8 dispatch call requested");
    dispatch_request.id = "evt-v8-point-003".into();
    dispatch_request.data = Some(RunEventData::ToolCallRequested {
        call: dispatch_call.clone(),
        status: ToolCallStatus::Requested,
    });
    let mut dispatch_approval = event(4, EventType::Approval, "V8 dispatch approved");
    dispatch_approval.id = "evt-v8-point-004".into();
    dispatch_approval.approval = Some(Approval {
        id: dispatch_approval_id.into(),
        status: ApprovalStatus::Approved,
        action: "allow dispatch v8 call".into(),
        tool: dispatch_call.tool.clone(),
        change: "exercise migrated dispatch lookup".into(),
        requires_approval: true,
        call_id: Some(dispatch_call.call_id.clone()),
        policy_revision: Some("rev-v8-point".into()),
        arguments_digest: Some(dispatch_call.arguments_digest.clone()),
        sandbox_profile: Some(dispatch_call.sandbox_profile.clone()),
        scope: Some(ApprovalScope::AllowOnce),
    });
    dispatch_approval.data = Some(RunEventData::ApprovalDecided {
        approval_id: dispatch_approval_id.into(),
        call_id: dispatch_call.call_id.clone(),
        decision: ReviewDecision::Approve,
        status: ToolCallStatus::Queued,
    });

    for event in [
        pending_request,
        pending_approval,
        dispatch_request,
        dispatch_approval,
    ] {
        connection
            .execute(
                r#"INSERT INTO run_events(
                       run_id, sequence, event_id, event_kind, payload_version, payload_json
                   ) VALUES (?1, ?2, ?3, ?4, 2, ?5)"#,
                params![
                    run_id,
                    event.sequence,
                    event.id,
                    event_kind(&event.event_type),
                    serde_json::to_string(&event).unwrap(),
                ],
            )
            .unwrap();
    }
    connection
        .execute(
            r#"INSERT INTO dispatch_jobs(
                   call_id, run_id, approval_id, approval_event_sequence,
                   approving_actor_user_id, tool_name, tool_version, effect, args_json,
                   args_digest, policy_id, policy_revision, sandbox_profile, status, attempt,
                   result_json, authorization_error_json, queued_at, started_at, finished_at,
                   start_event_sequence, result_event_sequence
               ) VALUES (
                   ?1, ?2, ?3, 4, 'user-v8-owner', ?4, ?5, 'local_write', ?6,
                   ?7, 'local-alpha', 'rev-v8-point', 'workspace_write', 'queued', 0,
                   NULL, NULL, ?8, NULL, NULL, NULL, NULL
               )"#,
            params![
                dispatch_call.call_id,
                run_id,
                dispatch_approval_id,
                dispatch_call.tool,
                dispatch_call.tool_version,
                serde_json::to_string(&dispatch_call.arguments).unwrap(),
                dispatch_call.arguments_digest,
                timestamp,
            ],
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

fn run_event_payloads(path: &Path, run_id: &str) -> Vec<String> {
    let connection = rusqlite::Connection::open(path).unwrap();
    let mut statement = connection
        .prepare("SELECT payload_json FROM run_events WHERE run_id = ?1 ORDER BY sequence")
        .unwrap();
    statement
        .query_map([run_id], |row| row.get::<_, String>(0))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap()
}

fn explain_query_plan<P: rusqlite::Params>(
    connection: &rusqlite::Connection,
    sql: &str,
    params: P,
) -> String {
    let mut statement = connection
        .prepare(&format!("EXPLAIN QUERY PLAN {sql}"))
        .unwrap();
    statement
        .query_map(params, |row| row.get::<_, String>(3))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap()
        .join("\n")
}

#[allow(clippy::too_many_arguments)]
fn replace_run_event_for_test(
    path: &Path,
    run_id: &str,
    sequence: i64,
    event: &RunEvent,
    data_kind: Option<&str>,
    call_id: Option<&str>,
    approval_id: Option<&str>,
    approval_status: Option<&str>,
    policy_revision: Option<&str>,
) {
    let connection = rusqlite::Connection::open(path).unwrap();
    connection
        .execute_batch("DROP TRIGGER run_events_reject_update;")
        .unwrap();
    assert_eq!(
        connection
            .execute(
                r#"UPDATE run_events
                   SET event_id = ?1, event_kind = ?2, payload_version = ?3,
                       payload_json = ?4, data_kind = ?5, call_id = ?6,
                       approval_id = ?7, approval_status = ?8, policy_revision = ?9
                   WHERE run_id = ?10 AND sequence = ?11"#,
                params![
                    event.id,
                    event_kind(&event.event_type),
                    if event.data.is_some() { 2 } else { 1 },
                    serde_json::to_string(event).unwrap(),
                    data_kind,
                    call_id,
                    approval_id,
                    approval_status,
                    policy_revision,
                    run_id,
                    sequence,
                ],
            )
            .unwrap(),
        1
    );
    connection
        .execute_batch(
            r#"CREATE TRIGGER run_events_reject_update
               BEFORE UPDATE ON run_events
               BEGIN
                   SELECT RAISE(ABORT, 'run_events are append-only');
               END;"#,
        )
        .unwrap();
}
