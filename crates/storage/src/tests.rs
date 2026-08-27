use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    process::Command,
    sync::{
        Arc, Barrier,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use deployment::{
    AgentDeployment, AgentSpec, ManifestEnvelope, ManifestPolicy, ManifestPromptBinding,
    ManifestProvider, ManifestTool,
};
use protocol::{
    AgentToolCallStatus, AgentTurnStatus, Approval, ApprovalScope, ApprovalStatus,
    AssistantReplyKind, AssistantReplyProvenance, AttachRunRequest, CreateSessionRequest,
    EventType, EvidenceSummary, FlushSessionRequest, IncidentStatus, IncidentSummary, Metric,
    MetricTone, NotDispatchedReason, PolicyDecision, ResumeSessionRequest, ReviewDecision,
    ReviewResponse, RunEvent, RunEventData, RunStatus, RunSummary, SandboxProfile, SessionEvent,
    SessionEventData, SessionStatus, SessionTurnStatus, Severity, StartTurnRequest, ToolCall,
    ToolCallStatus, ToolEffect, ToolExecutorStatus, ToolOutcome, ToolPolicySummary,
};
use rusqlite::{OptionalExtension, params};
use serde_json::{Value, json};
use tenancy::{PasswordAuthenticator, PasswordHashRecord};

use crate::{
    AccountAuditCheckpointCommit, AccountId, AgentModelClaimOutcome, AgentModelCompletion,
    AgentModelFailureCommit, AgentModelResolution, AgentModelStartOutcome, AgentModelSuccessCommit,
    AgentReviewCommit, AgentToolCallSpec, AgentToolClaimOutcome, AgentToolCompletion,
    AgentToolCompletionCommit, AgentTurnSpec, AuthSessionCommit, AuthSessionId, AuthzContext,
    BootstrapOwnerCommit, ClaimOutcome, CommitOutcome, CreateMemberCommit, DispatchCompleteCommit,
    DispatchJobSpec, DispatchRecoveryCommit, DispatchStartCommit, DispatchStatus,
    MemberSetupCommit, MemberSetupToken, MembershipRevision, MembershipRole, ReplyClaimOutcome,
    ReplyFailureCommit, ReplyJobSpec, ReplyJobStatus, ReplyOutcomeUnknownCommit,
    ReplySuccessCommit, ReviewCommit, RotateMemberSetupTokenCommit, RunSnapshot, RuntimeIdentity,
    SqliteOperationLimits, SqlitePhysicalLimits, SqliteStore, StorageError, StorageLimits,
    StoredMembershipStatus, StoredUserRole, StoredUserStatus, TransitionMemberCommit,
    UpdateAccountAuditPolicyCommit,
};

static NEXT_DATABASE: AtomicU64 = AtomicU64::new(0);
const RUN_ID: &str = "ZR-1842";
const LOCK_HELPER_DATABASE: &str = "ZEUS_STORAGE_LOCK_HELPER_DATABASE";
const LOCK_HELPER_READY: &str = "ZEUS_STORAGE_LOCK_HELPER_READY";
const LOCK_HELPER_RELEASE: &str = "ZEUS_STORAGE_LOCK_HELPER_RELEASE";
const TEST_OWNER_AUTH_SESSION_ID: &str = "asi_test_owner";
const TEST_FOREIGN_AUTH_SESSION_ID: &str = "asi_test_foreign";

fn test_owner_auth_session_id() -> AuthSessionId {
    AuthSessionId::from_persistence(TEST_OWNER_AUTH_SESSION_ID).unwrap()
}

fn owner_authz() -> AuthzContext {
    owner_authz_with_session(TEST_OWNER_AUTH_SESSION_ID)
}

fn owner_authz_with_session(auth_session_id: &str) -> AuthzContext {
    AuthzContext {
        account_id: AccountId::local(),
        user_id: "user-owner".into(),
        membership_role: MembershipRole::Owner,
        membership_revision: MembershipRevision::new(1).unwrap(),
        auth_session_id: AuthSessionId::from_persistence(auth_session_id).unwrap(),
    }
}

fn foreign_authz() -> AuthzContext {
    AuthzContext {
        account_id: AccountId::local(),
        user_id: "foreign-user".into(),
        membership_role: MembershipRole::Member,
        membership_revision: MembershipRevision::new(1).unwrap(),
        auth_session_id: AuthSessionId::from_persistence(TEST_FOREIGN_AUTH_SESSION_ID).unwrap(),
    }
}

fn member_authz() -> AuthzContext {
    AuthzContext {
        account_id: AccountId::local(),
        user_id: "user-member".into(),
        membership_role: MembershipRole::Member,
        membership_revision: MembershipRevision::new(1).unwrap(),
        auth_session_id: AuthSessionId::from_persistence("asi_test_member").unwrap(),
    }
}

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
    assert_eq!(first.operation_limits(), &SqliteOperationLimits::default());
    assert_eq!(second.operation_limits(), &SqliteOperationLimits::default());
    first.readiness().await.unwrap();
    second.readiness().await.unwrap();
}

fn test_operation_limits(
    max_concurrent_operations: usize,
    reserved_progress_operations: usize,
) -> SqliteOperationLimits {
    SqliteOperationLimits {
        max_concurrent_operations,
        reserved_progress_operations,
        acquire_timeout_ms: 1_000,
    }
}

async fn operation_limited_store(
    path: impl AsRef<Path>,
    operation_limits: SqliteOperationLimits,
) -> SqliteStore {
    SqliteStore::open_with_limits_and_physical_and_operations(
        path,
        StorageLimits::default(),
        SqlitePhysicalLimits::default(),
        operation_limits,
    )
    .await
    .unwrap()
}

async fn wait_for_operation_snapshot(
    store: &SqliteStore,
    predicate: impl Fn((usize, usize)) -> bool,
) {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if predicate(store.operation_test_snapshot()) {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("operation limiter state did not converge");
}

#[tokio::test]
async fn file_store_clones_share_the_bounded_general_operation_lane() {
    let database = TestDatabase::new();
    let operation_limits = test_operation_limits(2, 1);
    let store = operation_limited_store(database.path(), operation_limits.clone()).await;
    let clone = store.clone();
    assert_eq!(store.operation_limits(), &operation_limits);

    let (started_tx, started_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let blocker = tokio::spawn(async move {
        clone
            .test_general_operation(move |_| {
                let _ = started_tx.send(());
                release_rx.recv().unwrap();
                Ok(())
            })
            .await
    });
    started_rx.await.unwrap();

    let rejected_started = Arc::new(AtomicBool::new(false));
    let rejected_started_in_operation = Arc::clone(&rejected_started);
    let error = store
        .test_general_operation(move |_| {
            rejected_started_in_operation.store(true, Ordering::SeqCst);
            Ok(())
        })
        .await
        .unwrap_err();
    assert!(matches!(error, StorageError::OperationCapacityExceeded));
    assert!(!rejected_started.load(Ordering::SeqCst));

    release_tx.send(()).unwrap();
    blocker.await.unwrap().unwrap();
}

#[tokio::test]
async fn operation_permits_are_released_after_success_and_error() {
    let store = operation_limited_store(":memory:", test_operation_limits(2, 1)).await;

    assert_eq!(store.test_general_operation(|_| Ok(7_u8)).await.unwrap(), 7);
    assert!(matches!(
        store
            .test_general_operation::<(), _>(|_| Err(StorageError::InjectedFailure))
            .await,
        Err(StorageError::InjectedFailure)
    ));
    assert_eq!(store.test_general_operation(|_| Ok(9_u8)).await.unwrap(), 9);
}

#[tokio::test]
async fn aborted_caller_keeps_its_permit_until_the_blocking_closure_exits() {
    let database = TestDatabase::new();
    let store = operation_limited_store(database.path(), test_operation_limits(2, 1)).await;
    let blocker_store = store.clone();
    let (started_tx, started_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let blocker = tokio::spawn(async move {
        blocker_store
            .test_general_operation(move |_| {
                let _ = started_tx.send(());
                release_rx.recv().unwrap();
                Ok(())
            })
            .await
    });
    started_rx.await.unwrap();
    assert_eq!(store.operation_test_snapshot().0, 1);

    blocker.abort();
    assert!(blocker.await.unwrap_err().is_cancelled());
    assert!(matches!(
        store.test_general_operation(|_| Ok(())).await,
        Err(StorageError::OperationCapacityExceeded)
    ));
    assert_eq!(store.operation_test_snapshot().0, 1);

    release_tx.send(()).unwrap();
    wait_for_operation_snapshot(&store, |(active, _)| active == 0).await;
    store.test_general_operation(|_| Ok(())).await.unwrap();
}

#[tokio::test]
async fn memory_progress_waits_for_its_connection_before_entering_the_blocking_pool() {
    let store = operation_limited_store(":memory:", test_operation_limits(3, 1)).await;
    let first_store = store.clone();
    let (first_started_tx, first_started_rx) = tokio::sync::oneshot::channel();
    let (first_release_tx, first_release_rx) = std::sync::mpsc::channel();
    let first = tokio::spawn(async move {
        first_store
            .test_general_operation(move |_| {
                let _ = first_started_tx.send(());
                first_release_rx.recv().unwrap();
                Ok(())
            })
            .await
    });
    first_started_rx.await.unwrap();

    let progress_store = store.clone();
    let (progress_started_tx, progress_started_rx) = tokio::sync::oneshot::channel();
    let progress = tokio::spawn(async move {
        progress_store
            .test_progress_operation(move |_| {
                let _ = progress_started_tx.send(());
                Ok(())
            })
            .await
    });

    wait_for_operation_snapshot(&store, |(_, memory_waiters)| memory_waiters == 1).await;
    assert_eq!(store.operation_test_snapshot(), (1, 1));

    first_release_tx.send(()).unwrap();
    first.await.unwrap().unwrap();
    progress_started_rx.await.unwrap();
    progress.await.unwrap().unwrap();
    assert_eq!(store.operation_test_snapshot(), (0, 0));
}

#[tokio::test]
async fn durable_progress_uses_the_reserved_lane_when_general_work_is_saturated() {
    let database = TestDatabase::new();
    let store = operation_limited_store(database.path(), test_operation_limits(2, 1)).await;
    let blocker_store = store.clone();
    let (started_tx, started_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let blocker = tokio::spawn(async move {
        blocker_store
            .test_general_operation(move |_| {
                let _ = started_tx.send(());
                release_rx.recv().unwrap();
                Ok(())
            })
            .await
    });
    started_rx.await.unwrap();

    assert!(matches!(
        store.test_general_operation(|_| Ok(())).await,
        Err(StorageError::OperationCapacityExceeded)
    ));
    assert_eq!(
        store
            .test_progress_operation(|_| Ok("progress"))
            .await
            .unwrap(),
        "progress"
    );

    release_tx.send(()).unwrap();
    blocker.await.unwrap().unwrap();
}

#[tokio::test]
async fn member_enablement_cannot_consume_the_reserved_operation_lane() {
    let database = TestDatabase::new();
    let store = operation_limited_store(database.path(), test_operation_limits(2, 1)).await;
    bootstrap_test_owner(&store).await;

    for (user_id, username, auth_session_id, token_hash, csrf_hash) in [
        (
            "user-operation-enable-a",
            "operation-enable-a",
            "asi_operation_enable_a",
            "d",
            "8",
        ),
        (
            "user-operation-enable-b",
            "operation-enable-b",
            "asi_operation_enable_b",
            "e",
            "9",
        ),
    ] {
        let (token, presented) = member_setup_token_pair();
        store
            .create_member(
                &owner_authz(),
                CreateMemberCommit {
                    user_id: user_id.into(),
                    username: username.into(),
                    setup_token: token,
                },
            )
            .await
            .unwrap();
        let mut setup = member_setup_commit(&presented, auth_session_id, token_hash);
        setup.csrf_hash = csrf_hash.repeat(64);
        store.complete_member_setup(setup).await.unwrap();
    }

    store
        .transition_member(
            &owner_authz(),
            TransitionMemberCommit {
                user_id: "user-operation-enable-a".into(),
                expected_revision: MembershipRevision::new(1).unwrap(),
                expected_role: MembershipRole::Member,
                expected_status: StoredMembershipStatus::Active,
                role: MembershipRole::Member,
                status: StoredMembershipStatus::Disabled,
            },
        )
        .await
        .unwrap();

    let blocker_store = store.clone();
    let (started_tx, started_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let blocker = tokio::spawn(async move {
        blocker_store
            .test_general_operation(move |_| {
                let _ = started_tx.send(());
                release_rx.recv().unwrap();
                Ok(())
            })
            .await
    });
    started_rx.await.unwrap();

    assert!(matches!(
        store
            .transition_member(
                &owner_authz(),
                TransitionMemberCommit {
                    user_id: "user-operation-enable-a".into(),
                    expected_revision: MembershipRevision::new(2).unwrap(),
                    expected_role: MembershipRole::Member,
                    expected_status: StoredMembershipStatus::Disabled,
                    role: MembershipRole::Member,
                    status: StoredMembershipStatus::Disabled,
                },
            )
            .await,
        Err(StorageError::OperationCapacityExceeded)
    ));

    assert!(matches!(
        store
            .transition_member(
                &owner_authz(),
                TransitionMemberCommit {
                    user_id: "user-operation-enable-a".into(),
                    expected_revision: MembershipRevision::new(2).unwrap(),
                    expected_role: MembershipRole::Member,
                    expected_status: StoredMembershipStatus::Disabled,
                    role: MembershipRole::Member,
                    status: StoredMembershipStatus::Active,
                },
            )
            .await,
        Err(StorageError::OperationCapacityExceeded)
    ));

    assert!(matches!(
        store
            .transition_member(
                &owner_authz(),
                TransitionMemberCommit {
                    user_id: "user-operation-enable-b".into(),
                    expected_revision: MembershipRevision::new(1).unwrap(),
                    expected_role: MembershipRole::Member,
                    expected_status: StoredMembershipStatus::Active,
                    role: MembershipRole::Owner,
                    status: StoredMembershipStatus::Disabled,
                },
            )
            .await,
        Err(StorageError::OperationCapacityExceeded)
    ));

    let revoked = store
        .transition_member(
            &owner_authz(),
            TransitionMemberCommit {
                user_id: "user-operation-enable-b".into(),
                expected_revision: MembershipRevision::new(1).unwrap(),
                expected_role: MembershipRole::Member,
                expected_status: StoredMembershipStatus::Active,
                role: MembershipRole::Member,
                status: StoredMembershipStatus::Disabled,
            },
        )
        .await
        .unwrap();
    assert_eq!(revoked.member.status, StoredMembershipStatus::Disabled);

    release_tx.send(()).unwrap();
    blocker.await.unwrap().unwrap();
}

#[tokio::test]
async fn durable_progress_times_out_before_spawning_when_total_capacity_is_full() {
    let database = TestDatabase::new();
    let store = operation_limited_store(
        database.path(),
        SqliteOperationLimits {
            max_concurrent_operations: 2,
            reserved_progress_operations: 1,
            acquire_timeout_ms: 20,
        },
    )
    .await;

    let general_store = store.clone();
    let (general_started_tx, general_started_rx) = tokio::sync::oneshot::channel();
    let (general_release_tx, general_release_rx) = std::sync::mpsc::channel();
    let general = tokio::spawn(async move {
        general_store
            .test_general_operation(move |_| {
                let _ = general_started_tx.send(());
                general_release_rx.recv().unwrap();
                Ok(())
            })
            .await
    });
    general_started_rx.await.unwrap();

    let progress_store = store.clone();
    let (progress_started_tx, progress_started_rx) = tokio::sync::oneshot::channel();
    let (progress_release_tx, progress_release_rx) = std::sync::mpsc::channel();
    let progress = tokio::spawn(async move {
        progress_store
            .test_progress_operation(move |_| {
                let _ = progress_started_tx.send(());
                progress_release_rx.recv().unwrap();
                Ok(())
            })
            .await
    });
    progress_started_rx.await.unwrap();

    let rejected_started = Arc::new(AtomicBool::new(false));
    let rejected_started_in_operation = Arc::clone(&rejected_started);
    assert!(matches!(
        store
            .test_progress_operation(move |_| {
                rejected_started_in_operation.store(true, Ordering::SeqCst);
                Ok(())
            })
            .await,
        Err(StorageError::OperationCapacityExceeded)
    ));
    assert!(!rejected_started.load(Ordering::SeqCst));

    general_release_tx.send(()).unwrap();
    progress_release_tx.send(()).unwrap();
    general.await.unwrap().unwrap();
    progress.await.unwrap().unwrap();
    store.test_general_operation(|_| Ok(())).await.unwrap();
    store.test_progress_operation(|_| Ok(())).await.unwrap();
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
                &owner_authz(),
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
        .commit_review_for_actor(
            &owner_authz(),
            approved_dispatch_commit(&snapshot, "legacy-policy"),
        )
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
        .review_context_for_actor(&owner_authz(), RUN_ID, "APR-901")
        .await
        .unwrap();
    assert_eq!(review.snapshot, full.snapshot);
    assert_eq!(review.approval, events[5].approval);
    assert_eq!(review.approval_event_sequence, Some(6));
    assert_eq!(review.requested_call, Some(dispatch_fixture_call()));
    assert_eq!(review.requested_call_event_sequence, Some(4));
    assert!(matches!(
        store
            .review_context_for_actor(&foreign_authz(), RUN_ID, "missing-approval")
            .await,
        Err(StorageError::AuthSessionNotFound)
    ));

    let commit = approved_dispatch_commit(&snapshot, "point-context-review");
    store
        .commit_review_for_actor(&owner_authz(), commit.clone())
        .await
        .unwrap();
    let settled_review = store
        .review_context_for_actor(&owner_authz(), RUN_ID, "APR-901")
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
            &owner_authz(),
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
            &owner_authz(),
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
            .review_context_for_actor(&foreign_authz(), RUN_ID, "APR-901")
            .await,
        Err(StorageError::AuthSessionNotFound)
    ));
    assert!(matches!(
        duplicate_store
            .review_context_for_actor(&owner_authz(), RUN_ID, "APR-901")
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
        store
            .commit_review_for_actor(&owner_authz(), oversized)
            .await,
        Err(StorageError::InvalidResourceEnvelope(_))
    ));
    assert!(
        store
            .review_receipt_for_actor(&owner_authz(), RUN_ID, "oversized-review-note")
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
            .commit_review_for_actor(&owner_authz(), boundary)
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
            .load_run_for_actor(&owner_authz(), &long_run_id)
            .await
            .unwrap()
            .snapshot
            .run
            .id,
        long_run_id
    );
    assert_eq!(
        reopened
            .events_after_for_actor(&owner_authz(), &long_run_id, 0)
            .await
            .unwrap()
            .len(),
        6
    );
    let legacy_page = reopened
        .run_event_page_for_actor(&owner_authz(), &long_run_id, 0, 3)
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
            .commit_review_for_actor(&owner_authz(), commit.clone())
            .await
            .unwrap(),
        CommitOutcome::Committed
    );
    let receipt = reopened
        .review_receipt_for_actor(
            &owner_authz(),
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
                   account_id, actor_user_id, idempotency_key, operation, request_fingerprint,
                   response_json, run_id, event_sequence, created_at
               ) VALUES (
                   'acc_local', 'user-owner', 'legacy-long-note-receipt', 'review', ?1,
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
                &owner_authz(),
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
    let store =
        seeded_file_store_with_operation_limits(database.path(), test_operation_limits(9, 1)).await;
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
        store
            .commit_review_with_failure(&owner_authz(), commit.clone())
            .await,
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
        store
            .commit_review_for_actor(&owner_authz(), commit)
            .await
            .unwrap(),
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
    assert_eq!(
        versions,
        vec![
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21,
        ]
    );
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
    let account_backfill: (String, String, String, i64) = connection
        .query_row(
            r#"SELECT
                   (SELECT account_id FROM incidents WHERE id = 'INC-2048'),
                   (SELECT account_id FROM runs WHERE id = 'ZR-1842'),
                   (SELECT account_id FROM sessions WHERE id = 'session-ZR-1842'),
                   (SELECT COUNT(*) FROM account_memberships)"#,
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .unwrap();
    assert_eq!(
        account_backfill,
        (
            "acc_local".into(),
            "acc_local".into(),
            "acc_local".into(),
            0
        )
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
        "v9-v21 migrations must not rewrite immutable event payloads"
    );
    let connection = rusqlite::Connection::open(database.path()).unwrap();
    let version: i64 = connection
        .query_row("SELECT MAX(version) FROM schema_migrations", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(version, 21);
    let configured_account: (String, String, String, i64) = connection
        .query_row(
            r#"SELECT
                   (SELECT account_id FROM runs WHERE id = ?1),
                   (SELECT account_id FROM incidents WHERE id = 'INC-V8-POINT'),
                   (SELECT role FROM account_memberships
                    WHERE account_id = 'acc_local' AND user_id = 'user-v8-owner'),
                   (SELECT revision FROM account_memberships
                    WHERE account_id = 'acc_local' AND user_id = 'user-v8-owner')"#,
            [long_run_id.as_str()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .unwrap();
    assert_eq!(
        configured_account,
        ("acc_local".into(), "acc_local".into(), "owner".into(), 1)
    );
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
async fn v12_member_owned_history_aborts_v13_without_partial_account_schema() {
    let database = TestDatabase::new();
    let store = SqliteStore::open(database.path()).await.unwrap();
    bootstrap_test_owner(&store).await;
    insert_test_member(database.path(), "user-member", "member");
    activate_test_member_auth(database.path(), "user-member", "asi_test_member");
    store
        .create_session_for_actor(
            &member_authz(),
            CreateSessionRequest {
                id: "session-member-history".into(),
                title: "Member-owned legacy history".into(),
            },
            "create-member-history",
        )
        .await
        .unwrap();
    drop(store);

    let connection = rusqlite::Connection::open(database.path()).unwrap();
    downgrade_account_foundation_fixture_to_v12(&connection);
    drop(connection);

    let error = match SqliteStore::open(database.path()).await {
        Ok(_) => panic!("member-owned v12 history must not be assigned to the local account"),
        Err(error) => error,
    };
    assert!(matches!(
        error,
        StorageError::CorruptData(message)
            if message.contains("configured session is not owned by the legacy owner")
    ));

    let connection = rusqlite::Connection::open(database.path()).unwrap();
    let state: (i64, i64, i64, String) = connection
        .query_row(
            r#"SELECT
                   (SELECT MAX(version) FROM schema_migrations),
                   (SELECT COUNT(*) FROM sqlite_schema
                    WHERE type = 'table' AND name = 'accounts'),
                   (SELECT COUNT(*) FROM pragma_table_info('sessions')
                    WHERE name = 'account_id'),
                   (SELECT owner_user_id FROM sessions
                    WHERE id = 'session-member-history')"#,
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .unwrap();
    assert_eq!(state, (12, 0, 0, "user-member".into()));
}

#[tokio::test]
async fn v12_foreign_key_corruption_aborts_v13_before_writing_account_state() {
    let database = TestDatabase::new();
    let store = SqliteStore::open(database.path()).await.unwrap();
    bootstrap_test_owner(&store).await;
    drop(store);

    let connection = rusqlite::Connection::open(database.path()).unwrap();
    downgrade_account_foundation_fixture_to_v12(&connection);
    connection
        .pragma_update(None, "foreign_keys", false)
        .unwrap();
    connection
        .execute(
            r#"INSERT INTO user_preferences(
                   user_id, theme, preferred_model, revision, updated_at
               ) VALUES (
                   'missing-user', 'system', NULL, 1, '2026-08-27T00:00:00.000Z'
               )"#,
            [],
        )
        .unwrap();
    drop(connection);

    let error = match SqliteStore::open(database.path()).await {
        Ok(_) => panic!("foreign-key-corrupt v12 state must not migrate"),
        Err(error) => error,
    };
    assert!(matches!(
        error,
        StorageError::CorruptData(message)
            if message.contains("foreign key violation in `user_preferences`")
    ));
    let connection = rusqlite::Connection::open(database.path()).unwrap();
    assert_eq!(
        connection
            .query_row("SELECT MAX(version) FROM schema_migrations", [], |row| {
                row.get::<_, i64>(0)
            })
            .unwrap(),
        12
    );
    assert_eq!(
        connection
            .query_row(
                "SELECT COUNT(*) FROM sqlite_schema WHERE type = 'table' AND name = 'accounts'",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        0
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
            auth_session_id: test_owner_auth_session_id(),
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
        .update_preferences(&owner_authz(), 1, "dark", Some("local-fallback"))
        .await
        .unwrap();
    assert_eq!(updated.theme, "dark");
    assert_eq!(updated.revision, 2);
    assert!(matches!(
        store
            .update_preferences(&owner_authz(), 1, "light", None)
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

    assert!(
        store
            .revoke_auth_session(&owner_authz(), &session_hash)
            .await
            .unwrap()
    );
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
                auth_session_id: test_owner_auth_session_id(),
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
async fn account_foundation_scopes_identity_roots_and_only_enrolls_the_bootstrap_owner() {
    let database = TestDatabase::new();
    let store = SqliteStore::open(database.path()).await.unwrap();
    store
        .bind_runtime_identity(production_identity())
        .await
        .unwrap();
    let (snapshot, events) = seed_fixture();
    assert!(store.seed_if_empty(snapshot, events).await.unwrap());
    assert!(
        store
            .seed_demo_session("session-ZR-1842", "Checkout API latency", RUN_ID)
            .await
            .unwrap()
    );
    store.verify_integrity().await.unwrap();

    let connection = rusqlite::Connection::open(database.path()).unwrap();
    let account: (String, String, String) = connection
        .query_row("SELECT id, name, status FROM accounts", [], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?))
        })
        .unwrap();
    assert_eq!(
        account,
        ("acc_local".into(), "Local".into(), "active".into())
    );
    let scopes: (String, String, String, String) = connection
        .query_row(
            r#"SELECT
                   (SELECT account_id FROM incidents WHERE id = 'INC-2048'),
                   (SELECT account_id FROM sessions WHERE id = 'session-ZR-1842'),
                   (SELECT account_id FROM runs WHERE id = 'ZR-1842'),
                   (SELECT account_id FROM runtime_identity WHERE singleton = 1)"#,
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .unwrap();
    assert_eq!(
        scopes,
        (
            "acc_local".into(),
            "acc_local".into(),
            "acc_local".into(),
            "acc_local".into()
        )
    );
    assert_eq!(
        connection
            .query_row("SELECT COUNT(*) FROM account_memberships", [], |row| {
                row.get::<_, i64>(0)
            })
            .unwrap(),
        0
    );
    drop(connection);

    bootstrap_test_owner(&store).await;
    insert_test_member(database.path(), "user-member", "member");
    let connection = rusqlite::Connection::open(database.path()).unwrap();
    let owner_membership: (String, String, String, i64) = connection
        .query_row(
            r#"SELECT account_id, role, status, revision
               FROM account_memberships WHERE user_id = 'user-owner'"#,
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .unwrap();
    assert_eq!(
        owner_membership,
        ("acc_local".into(), "owner".into(), "active".into(), 1)
    );
    assert_eq!(
        connection
            .query_row(
                "SELECT COUNT(*) FROM account_memberships WHERE user_id = 'user-member'",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        0,
        "legacy member users must not be enrolled implicitly"
    );
    drop(connection);
    store.verify_integrity().await.unwrap();
    drop(store);

    SqliteStore::open(database.path())
        .await
        .unwrap()
        .verify_integrity()
        .await
        .unwrap();
}

#[tokio::test]
async fn v12_identity_and_run_crash_prefix_migrates_then_recovers_the_primary_session() {
    let database = TestDatabase::new();
    let store = SqliteStore::open(database.path()).await.unwrap();
    store
        .bind_runtime_identity(production_identity())
        .await
        .unwrap();
    let (snapshot, events) = seed_fixture();
    assert!(store.seed_if_empty(snapshot, events).await.unwrap());
    drop(store);

    let connection = rusqlite::Connection::open(database.path()).unwrap();
    assert_eq!(
        connection
            .query_row("SELECT COUNT(*) FROM runs", [], |row| row.get::<_, i64>(0))
            .unwrap(),
        1
    );
    assert_eq!(
        connection
            .query_row("SELECT COUNT(*) FROM sessions", [], |row| row
                .get::<_, i64>(0))
            .unwrap(),
        0
    );
    downgrade_account_foundation_fixture_to_v12(&connection);
    drop(connection);

    let reopened = SqliteStore::open(database.path()).await.unwrap();
    reopened
        .bind_runtime_identity(production_identity())
        .await
        .unwrap();
    let (snapshot, events) = seed_fixture();
    assert!(!reopened.seed_if_empty(snapshot, events).await.unwrap());
    assert!(
        reopened
            .seed_demo_session("session-ZR-1842", "Checkout API latency", RUN_ID)
            .await
            .unwrap()
    );
    reopened.verify_integrity().await.unwrap();

    let connection = rusqlite::Connection::open(database.path()).unwrap();
    let recovered: (i64, String, String, String) = connection
        .query_row(
            r#"SELECT
                   (SELECT MAX(version) FROM schema_migrations),
                   (SELECT account_id FROM runtime_identity WHERE singleton = 1),
                   (SELECT account_id FROM runs WHERE id = 'ZR-1842'),
                   (SELECT account_id FROM sessions WHERE id = 'session-ZR-1842')"#,
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .unwrap();
    assert_eq!(
        recovered,
        (
            21,
            "acc_local".into(),
            "acc_local".into(),
            "acc_local".into()
        )
    );
}

#[tokio::test]
async fn bootstrap_owner_rolls_back_membership_claims_and_token_on_late_failure() {
    let database = TestDatabase::new();
    let store = seeded_file_store(database.path()).await;
    store
        .create_session(
            CreateSessionRequest {
                id: "session-bootstrap-rollback".into(),
                title: "Bootstrap rollback".into(),
            },
            "create-bootstrap-rollback",
        )
        .await
        .unwrap();
    let expiry = (chrono::Utc::now() + chrono::Duration::hours(1))
        .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    let commit = BootstrapOwnerCommit {
        bootstrap_token_hash: "a".repeat(64),
        auth_session_id: test_owner_auth_session_id(),
        user_id: "user-owner".into(),
        username: "owner".into(),
        password_hash: "$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$ZGlnaWVzdA".into(),
        session_token_hash: "b".repeat(64),
        csrf_hash: "c".repeat(64),
        session_expires_at: expiry.clone(),
    };
    store
        .replace_bootstrap_token(&commit.bootstrap_token_hash, &expiry)
        .await
        .unwrap();
    let connection = rusqlite::Connection::open(database.path()).unwrap();
    connection
        .execute_batch(
            r#"CREATE TRIGGER auth_sessions_inject_bootstrap_failure
               BEFORE INSERT ON auth_sessions
               BEGIN
                   SELECT RAISE(ABORT, 'injected auth session failure');
               END;"#,
        )
        .unwrap();
    drop(connection);

    assert!(matches!(
        store.bootstrap_owner(commit.clone()).await,
        Err(StorageError::Sqlite(_))
    ));
    let connection = rusqlite::Connection::open(database.path()).unwrap();
    let rolled_back: (i64, i64, i64, i64, i64, i64, i64) = connection
        .query_row(
            r#"SELECT
                   (SELECT COUNT(*) FROM users),
                   (SELECT COUNT(*) FROM user_preferences),
                   (SELECT COUNT(*) FROM account_memberships),
                   (SELECT COUNT(*) FROM auth_sessions),
                   (SELECT COUNT(*) FROM sessions WHERE owner_user_id IS NOT NULL),
                   (SELECT COUNT(*) FROM runs WHERE owner_user_id IS NOT NULL),
                   (SELECT COUNT(*) FROM bootstrap_tokens WHERE terminal_at IS NULL)"#,
            [],
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
    assert_eq!(rolled_back, (0, 0, 0, 0, 0, 0, 1));
    assert_eq!(
        connection
            .query_row(
                "SELECT COUNT(*) FROM session_command_receipts WHERE actor_user_id IS NULL",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        1
    );
    connection
        .execute_batch("DROP TRIGGER auth_sessions_inject_bootstrap_failure;")
        .unwrap();
    drop(connection);

    store.bootstrap_owner(commit).await.unwrap();
    let connection = rusqlite::Connection::open(database.path()).unwrap();
    assert_eq!(
        connection
            .query_row(
                r#"SELECT COUNT(*)
                   FROM account_memberships
                   WHERE account_id = 'acc_local'
                     AND user_id = 'user-owner'
                     AND role = 'owner'
                     AND status = 'active'
                     AND revision = 1"#,
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        1
    );
    drop(connection);
    store.verify_integrity().await.unwrap();
}

#[tokio::test]
async fn account_membership_triggers_enforce_revision_durability_and_last_owner() {
    let database = TestDatabase::new();
    let store = SqliteStore::open(database.path()).await.unwrap();
    bootstrap_test_owner(&store).await;
    insert_test_member(database.path(), "user-member", "member");
    let connection = rusqlite::Connection::open(database.path()).unwrap();
    connection
        .pragma_update(None, "foreign_keys", true)
        .unwrap();
    connection
        .execute(
            r#"INSERT INTO account_memberships(
                   account_id, user_id, role, status, revision, created_at, updated_at
               ) VALUES (
                   'acc_local', 'user-member', 'member', 'active', 1,
                   '2026-08-27T00:00:00.000Z', '2026-08-27T00:00:00.000Z'
               )"#,
            [],
        )
        .unwrap();

    assert!(
        connection
            .execute(
                r#"UPDATE account_memberships
                   SET status = 'disabled', revision = 3,
                       updated_at = '2999-01-01T00:00:00.000Z'
                   WHERE account_id = 'acc_local' AND user_id = 'user-member'"#,
                [],
            )
            .is_err()
    );
    assert_eq!(
        connection
            .execute(
                r#"UPDATE account_memberships
                   SET status = 'disabled', revision = 2,
                       updated_at = '2999-01-01T00:00:00.000Z'
                   WHERE account_id = 'acc_local' AND user_id = 'user-member'"#,
                [],
            )
            .unwrap(),
        1
    );
    assert!(
        connection
            .execute(
                "DELETE FROM account_memberships WHERE user_id = 'user-member'",
                [],
            )
            .is_err()
    );
    assert!(
        connection
            .execute(
                r#"UPDATE account_memberships
                   SET status = 'disabled', revision = 2,
                       updated_at = '2999-01-01T00:00:00.000Z'
                   WHERE account_id = 'acc_local' AND user_id = 'user-owner'"#,
                [],
            )
            .is_err()
    );
    assert!(
        connection
            .execute(
                r#"INSERT OR REPLACE INTO account_memberships(
                       account_id, user_id, role, status, revision, created_at, updated_at
                   ) SELECT account_id, user_id, role, status, revision, created_at, updated_at
                     FROM account_memberships WHERE user_id = 'user-owner'"#,
                [],
            )
            .is_err()
    );
}

#[tokio::test]
async fn member_lifecycle_recovers_pending_disable_enable_and_revokes_completed_sessions() {
    let database = TestDatabase::new();
    let store = SqliteStore::open(database.path()).await.unwrap();
    bootstrap_test_owner(&store).await;

    let (initial_token, initial_presented) = member_setup_token_pair();
    let created = store
        .create_member(
            &owner_authz(),
            CreateMemberCommit {
                user_id: "user-lifecycle".into(),
                username: "lifecycle".into(),
                setup_token: initial_token,
            },
        )
        .await
        .unwrap();
    assert!(!created.replayed);
    assert!(created.member.setup_required);
    assert!(created.member.setup_token_expires_at.is_some());
    assert_eq!(created.member.revision.get(), 1);
    let create_replay = store
        .create_member(
            &owner_authz(),
            CreateMemberCommit {
                user_id: "user-lifecycle".into(),
                username: "lifecycle".into(),
                setup_token: MemberSetupToken::from_presented(&initial_presented).unwrap(),
            },
        )
        .await
        .unwrap();
    assert!(create_replay.replayed);
    assert_eq!(create_replay.member, created.member);

    let pending_disabled = store
        .transition_member(
            &owner_authz(),
            TransitionMemberCommit {
                user_id: "user-lifecycle".into(),
                expected_revision: MembershipRevision::new(1).unwrap(),
                expected_role: MembershipRole::Member,
                expected_status: StoredMembershipStatus::Active,
                role: MembershipRole::Member,
                status: StoredMembershipStatus::Disabled,
            },
        )
        .await
        .unwrap();
    assert!(pending_disabled.member.setup_required);
    assert!(pending_disabled.member.setup_token_expires_at.is_none());
    assert_eq!(pending_disabled.revoked_setup_tokens, 1);

    let pending_enabled = store
        .transition_member(
            &owner_authz(),
            TransitionMemberCommit {
                user_id: "user-lifecycle".into(),
                expected_revision: MembershipRevision::new(2).unwrap(),
                expected_role: MembershipRole::Member,
                expected_status: StoredMembershipStatus::Disabled,
                role: MembershipRole::Member,
                status: StoredMembershipStatus::Active,
            },
        )
        .await
        .unwrap();
    assert!(pending_enabled.member.setup_required);
    assert!(pending_enabled.member.setup_token_expires_at.is_none());
    assert!(matches!(
        store
            .complete_member_setup(member_setup_commit(
                &initial_presented,
                "asi_lifecycle_stale",
                "d",
            ))
            .await,
        Err(StorageError::InvalidMemberSetupToken)
    ));

    let (recovery_token, recovery_presented) = member_setup_token_pair();
    let rotated = store
        .rotate_member_setup_token(
            &owner_authz(),
            RotateMemberSetupTokenCommit {
                user_id: "user-lifecycle".into(),
                expected_revision: MembershipRevision::new(3).unwrap(),
                setup_token: recovery_token,
            },
        )
        .await
        .unwrap();
    assert!(rotated.member.setup_required);
    assert!(rotated.member.setup_token_expires_at.is_some());
    let rotate_replay = store
        .rotate_member_setup_token(
            &owner_authz(),
            RotateMemberSetupTokenCommit {
                user_id: "user-lifecycle".into(),
                expected_revision: MembershipRevision::new(3).unwrap(),
                setup_token: MemberSetupToken::from_presented(&recovery_presented).unwrap(),
            },
        )
        .await
        .unwrap();
    assert!(rotate_replay.replayed);
    assert_eq!(rotate_replay.member, rotated.member);

    let setup = store
        .complete_member_setup(member_setup_commit(
            &recovery_presented,
            "asi_lifecycle_member",
            "e",
        ))
        .await
        .unwrap();
    assert!(!setup.member.setup_required);
    assert!(setup.member.setup_token_expires_at.is_none());
    assert_eq!(setup.principal.authz.membership_revision.get(), 3);
    assert!(store.authenticate(&"e".repeat(64)).await.unwrap().is_some());
    assert!(matches!(
        store
            .complete_member_setup(member_setup_commit(
                &recovery_presented,
                "asi_lifecycle_replay",
                "f",
            ))
            .await,
        Err(StorageError::InvalidMemberSetupToken)
    ));

    let disabled = store
        .transition_member(
            &owner_authz(),
            TransitionMemberCommit {
                user_id: "user-lifecycle".into(),
                expected_revision: MembershipRevision::new(3).unwrap(),
                expected_role: MembershipRole::Member,
                expected_status: StoredMembershipStatus::Active,
                role: MembershipRole::Member,
                status: StoredMembershipStatus::Disabled,
            },
        )
        .await
        .unwrap();
    assert!(!disabled.member.setup_required);
    assert_eq!(disabled.revoked_auth_sessions, 1);
    assert!(store.authenticate(&"e".repeat(64)).await.unwrap().is_none());

    let enabled = store
        .transition_member(
            &owner_authz(),
            TransitionMemberCommit {
                user_id: "user-lifecycle".into(),
                expected_revision: MembershipRevision::new(4).unwrap(),
                expected_role: MembershipRole::Member,
                expected_status: StoredMembershipStatus::Disabled,
                role: MembershipRole::Member,
                status: StoredMembershipStatus::Active,
            },
        )
        .await
        .unwrap();
    assert!(!enabled.member.setup_required);
    let actions = store
        .list_account_audit_events(&owner_authz(), None, 20)
        .await
        .unwrap()
        .items
        .into_iter()
        .map(|event| event.action)
        .collect::<Vec<_>>();
    assert_eq!(
        actions,
        vec![
            "member.enabled",
            "member.disabled",
            "member.setup_completed",
            "member.setup_token_rotated",
            "member.enabled",
            "member.disabled",
            "member.created",
        ]
    );
    store.verify_integrity().await.unwrap();
}

#[tokio::test]
async fn pending_member_password_sentinel_is_supported_and_never_verifies() {
    let database = TestDatabase::new();
    let store = SqliteStore::open(database.path()).await.unwrap();
    bootstrap_test_owner(&store).await;
    let (setup_token, _) = member_setup_token_pair();
    store
        .create_member(
            &owner_authz(),
            CreateMemberCommit {
                user_id: "user-pending-sentinel".into(),
                username: "pending-sentinel".into(),
                setup_token,
            },
        )
        .await
        .unwrap();
    let persisted: String = rusqlite::Connection::open(database.path())
        .unwrap()
        .query_row(
            "SELECT password_hash FROM users WHERE id = 'user-pending-sentinel'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let record = PasswordHashRecord::parse(persisted).unwrap();
    let authenticator = PasswordAuthenticator::new().unwrap();
    assert!(
        !authenticator
            .verify(Some(&record), "Wrong-password-2026")
            .unwrap()
    );
    assert!(
        store
            .credential_for_username("pending-sentinel")
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        store
            .credential_for_username("missing-pending-sentinel")
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn last_owner_rejection_is_atomic_and_does_not_revoke_the_owner_session() {
    let store = SqliteStore::open(":memory:").await.unwrap();
    bootstrap_test_owner(&store).await;
    let before = store.account_audit_state(&owner_authz()).await.unwrap();
    assert!(matches!(
        store
            .transition_member(
                &owner_authz(),
                TransitionMemberCommit {
                    user_id: "user-owner".into(),
                    expected_revision: MembershipRevision::new(1).unwrap(),
                    expected_role: MembershipRole::Owner,
                    expected_status: StoredMembershipStatus::Active,
                    role: MembershipRole::Member,
                    status: StoredMembershipStatus::Disabled,
                },
            )
            .await,
        Err(StorageError::LastAccountOwner)
    ));
    let owner = store
        .get_member(&owner_authz(), "user-owner")
        .await
        .unwrap();
    assert_eq!(owner.role, MembershipRole::Owner);
    assert_eq!(owner.status, StoredMembershipStatus::Active);
    assert_eq!(owner.revision.get(), 1);
    assert_eq!(
        store.account_audit_state(&owner_authz()).await.unwrap(),
        before
    );
}

#[tokio::test]
async fn expired_member_setup_is_non_consuming_visible_and_rotation_recovers() {
    let database = TestDatabase::new();
    let store = SqliteStore::open(database.path()).await.unwrap();
    bootstrap_test_owner(&store).await;
    let (token, presented) = member_setup_token_pair();
    store
        .create_member(
            &owner_authz(),
            CreateMemberCommit {
                user_id: "user-expired-setup".into(),
                username: "expired-setup".into(),
                setup_token: token,
            },
        )
        .await
        .unwrap();

    let connection = rusqlite::Connection::open(database.path()).unwrap();
    connection
        .execute_batch(
            r#"DROP TRIGGER member_setup_tokens_reject_update;
               UPDATE member_setup_tokens
               SET created_at = '2000-01-01T00:00:00.000Z',
                   expires_at = '2000-01-02T00:00:00.000Z'
               WHERE user_id = 'user-expired-setup';
               CREATE TRIGGER member_setup_tokens_reject_update
               BEFORE UPDATE ON member_setup_tokens
               BEGIN
                   SELECT RAISE(ABORT, 'member setup tokens are immutable; rotate by replacement');
               END;"#,
        )
        .unwrap();
    drop(connection);

    let expired = store
        .get_member(&owner_authz(), "user-expired-setup")
        .await
        .unwrap();
    assert!(expired.setup_required);
    assert_eq!(
        expired.setup_token_expires_at.as_deref(),
        Some("2000-01-02T00:00:00.000Z")
    );
    let audit_before = store.account_audit_state(&owner_authz()).await.unwrap();
    assert!(matches!(
        store
            .complete_member_setup(member_setup_commit(&presented, "asi_expired_setup", "6",))
            .await,
        Err(StorageError::MemberSetupExpired)
    ));
    assert_eq!(
        store.account_audit_state(&owner_authz()).await.unwrap(),
        audit_before
    );

    let (rotated_token, rotated_presented) = member_setup_token_pair();
    store
        .rotate_member_setup_token(
            &owner_authz(),
            RotateMemberSetupTokenCommit {
                user_id: "user-expired-setup".into(),
                expected_revision: MembershipRevision::new(1).unwrap(),
                setup_token: rotated_token,
            },
        )
        .await
        .unwrap();
    let completed = store
        .complete_member_setup(member_setup_commit(
            &rotated_presented,
            "asi_expired_setup_recovered",
            "7",
        ))
        .await
        .unwrap();
    assert!(!completed.member.setup_required);
}

#[tokio::test]
async fn account_audit_hash_chain_is_cursor_bounded_and_detects_valid_json_tampering() {
    let database = TestDatabase::new();
    let store = SqliteStore::open(database.path()).await.unwrap();
    bootstrap_test_owner(&store).await;
    for index in 0..3 {
        let (token, _) = member_setup_token_pair();
        store
            .create_member(
                &owner_authz(),
                CreateMemberCommit {
                    user_id: format!("user-audit-{index}"),
                    username: format!("audit-{index}"),
                    setup_token: token,
                },
            )
            .await
            .unwrap();
    }

    let first = store
        .list_account_audit_events(&owner_authz(), None, 2)
        .await
        .unwrap();
    assert_eq!(first.items.len(), 2);
    assert!(first.next_cursor.is_some());
    assert_eq!(first.items[0].sequence, 3);
    assert_eq!(first.items[1].sequence, 2);
    let second = store
        .list_account_audit_events(&owner_authz(), first.next_cursor.as_deref(), 2)
        .await
        .unwrap();
    assert_eq!(second.items.len(), 1);
    assert_eq!(second.items[0].sequence, 1);
    assert!(second.next_cursor.is_none());
    assert_eq!(second.items[0].previous_hash, "0".repeat(64));
    assert_eq!(second.items[1..].len(), 0);
    assert!(matches!(
        store
            .list_account_audit_events(&foreign_authz(), first.next_cursor.as_deref(), 0)
            .await,
        Err(StorageError::AuthSessionNotFound)
    ));
    store.verify_integrity().await.unwrap();

    let connection = rusqlite::Connection::open(database.path()).unwrap();
    connection
        .execute_batch(
            r#"DROP TRIGGER account_audit_events_reject_update;
               UPDATE account_audit_events
               SET metadata_json = '{"tampered":true}'
               WHERE account_id = 'acc_local' AND sequence = 2;
               CREATE TRIGGER account_audit_events_reject_update
               BEFORE UPDATE ON account_audit_events
               BEGIN
                   SELECT RAISE(ABORT, 'account audit events are append-only');
               END;"#,
        )
        .unwrap();
    drop(connection);
    assert!(matches!(
        store.verify_integrity().await,
        Err(StorageError::CorruptData(message))
            if message.contains("account audit event hash")
    ));
}

#[tokio::test]
async fn v15_reopen_fails_closed_when_an_audit_index_or_trigger_is_missing() {
    let missing_index_database = TestDatabase::new();
    drop(
        SqliteStore::open(missing_index_database.path())
            .await
            .unwrap(),
    );
    rusqlite::Connection::open(missing_index_database.path())
        .unwrap()
        .execute_batch("DROP INDEX account_audit_events_hash_idx;")
        .unwrap();
    let index_error = match SqliteStore::open(missing_index_database.path()).await {
        Ok(_) => panic!("a schema-v15 database missing an audit index must not reopen"),
        Err(error) => error,
    };
    assert!(matches!(
        index_error,
        StorageError::CorruptData(message)
            if message == "one or more point-query indexes are missing"
    ));

    let missing_trigger_database = TestDatabase::new();
    drop(
        SqliteStore::open(missing_trigger_database.path())
            .await
            .unwrap(),
    );
    rusqlite::Connection::open(missing_trigger_database.path())
        .unwrap()
        .execute_batch("DROP TRIGGER account_audit_events_reject_update;")
        .unwrap();
    let trigger_error = match SqliteStore::open(missing_trigger_database.path()).await {
        Ok(_) => panic!("a schema-v15 database missing an audit trigger must not reopen"),
        Err(error) => error,
    };
    assert!(matches!(
        trigger_error,
        StorageError::CorruptData(message)
            if message == "one or more durability triggers are missing"
    ));
}

#[tokio::test]
async fn legal_hold_uses_progress_reserve_at_ordinary_capacity_and_release_is_atomic() {
    let limits = StorageLimits {
        account_audit_detail_rows: 2,
        account_audit_rows_per_account: 3,
        account_audit_rows_global: 3,
        account_audit_progress_rows_per_account: 1,
        account_audit_progress_rows_global: 1,
        account_audit_compaction_batch: 1,
        ..StorageLimits::default()
    };
    let store = SqliteStore::open_with_limits(":memory:", limits)
        .await
        .unwrap();
    bootstrap_test_owner(&store).await;
    for index in 0..2 {
        let (token, _) = member_setup_token_pair();
        store
            .create_member(
                &owner_authz(),
                CreateMemberCommit {
                    user_id: format!("user-hold-{index}"),
                    username: format!("hold-{index}"),
                    setup_token: token,
                },
            )
            .await
            .unwrap();
    }
    let ordinary_full = store.account_audit_state(&owner_authz()).await.unwrap();
    assert_eq!(ordinary_full.detailed_rows, 2);
    assert_eq!(ordinary_full.ordinary_capacity_remaining, 0);
    assert_eq!(ordinary_full.progress_capacity_remaining, 1);

    assert!(matches!(
        store
            .update_account_audit_policy(
                &owner_authz(),
                UpdateAccountAuditPolicyCommit {
                    expected_revision: 0,
                    detail_rows: 2,
                    legal_hold: true,
                    archive_required: false,
                },
            )
            .await,
        Err(StorageError::AuditPolicyConflict)
    ));
    assert_eq!(
        store
            .account_audit_state(&owner_authz())
            .await
            .unwrap()
            .policy
            .revision,
        1
    );

    let held = store
        .update_account_audit_policy(
            &owner_authz(),
            UpdateAccountAuditPolicyCommit {
                expected_revision: 1,
                detail_rows: 2,
                legal_hold: true,
                archive_required: false,
            },
        )
        .await
        .unwrap();
    assert!(held.policy.legal_hold);
    assert_eq!(held.detailed_rows, 3);
    assert_eq!(held.progress_capacity_remaining, 0);
    assert!(matches!(
        store.readiness().await,
        Err(StorageError::AuditLegalHold)
    ));

    let (blocked_token, _) = member_setup_token_pair();
    assert!(matches!(
        store
            .create_member(
                &owner_authz(),
                CreateMemberCommit {
                    user_id: "user-hold-blocked".into(),
                    username: "hold-blocked".into(),
                    setup_token: blocked_token,
                },
            )
            .await,
        Err(StorageError::AuditLegalHold)
    ));
    assert!(matches!(
        store.get_member(&owner_authz(), "user-hold-blocked").await,
        Err(StorageError::MemberNotFound(_))
    ));
    assert_eq!(
        store
            .account_audit_state(&owner_authz())
            .await
            .unwrap()
            .detailed_rows,
        3
    );

    let released = store
        .update_account_audit_policy(
            &owner_authz(),
            UpdateAccountAuditPolicyCommit {
                expected_revision: 2,
                detail_rows: 2,
                legal_hold: false,
                archive_required: false,
            },
        )
        .await
        .unwrap();
    assert!(!released.policy.legal_hold);
    assert_eq!(released.rollup.through_sequence, 1);
    assert_eq!(released.detailed_rows, 3);
    store.readiness().await.unwrap();
}

#[tokio::test]
async fn legal_hold_reserves_the_last_progress_row_for_revocation_not_member_enablement() {
    let limits = StorageLimits {
        account_audit_detail_rows: 6,
        account_audit_rows_per_account: 7,
        account_audit_rows_global: 7,
        account_audit_progress_rows_per_account: 1,
        account_audit_progress_rows_global: 1,
        account_audit_compaction_batch: 1,
        ..StorageLimits::default()
    };
    let store = SqliteStore::open_with_limits(":memory:", limits)
        .await
        .unwrap();
    bootstrap_test_owner(&store).await;

    for (user_id, username, auth_session_id, token_hash, csrf_hash) in [
        (
            "user-hold-enable-a",
            "hold-enable-a",
            "asi_hold_enable_a",
            "d",
            "8",
        ),
        (
            "user-hold-enable-b",
            "hold-enable-b",
            "asi_hold_enable_b",
            "e",
            "9",
        ),
    ] {
        let (token, presented) = member_setup_token_pair();
        store
            .create_member(
                &owner_authz(),
                CreateMemberCommit {
                    user_id: user_id.into(),
                    username: username.into(),
                    setup_token: token,
                },
            )
            .await
            .unwrap();
        let mut setup = member_setup_commit(&presented, auth_session_id, token_hash);
        setup.csrf_hash = csrf_hash.repeat(64);
        store.complete_member_setup(setup).await.unwrap();
    }

    store
        .update_account_audit_policy(
            &owner_authz(),
            UpdateAccountAuditPolicyCommit {
                expected_revision: 1,
                detail_rows: 6,
                legal_hold: true,
                archive_required: false,
            },
        )
        .await
        .unwrap();
    store
        .transition_member(
            &owner_authz(),
            TransitionMemberCommit {
                user_id: "user-hold-enable-a".into(),
                expected_revision: MembershipRevision::new(1).unwrap(),
                expected_role: MembershipRole::Member,
                expected_status: StoredMembershipStatus::Active,
                role: MembershipRole::Member,
                status: StoredMembershipStatus::Disabled,
            },
        )
        .await
        .unwrap();
    let ordinary_full = store.account_audit_state(&owner_authz()).await.unwrap();
    assert_eq!(ordinary_full.detailed_rows, 6);
    assert_eq!(ordinary_full.ordinary_capacity_remaining, 0);
    assert_eq!(ordinary_full.progress_capacity_remaining, 1);

    assert!(matches!(
        store
            .transition_member(
                &owner_authz(),
                TransitionMemberCommit {
                    user_id: "user-hold-enable-a".into(),
                    expected_revision: MembershipRevision::new(2).unwrap(),
                    expected_role: MembershipRole::Member,
                    expected_status: StoredMembershipStatus::Disabled,
                    role: MembershipRole::Member,
                    status: StoredMembershipStatus::Active,
                },
            )
            .await,
        Err(StorageError::AuditLegalHold)
    ));
    let still_disabled = store
        .get_member(&owner_authz(), "user-hold-enable-a")
        .await
        .unwrap();
    assert_eq!(still_disabled.revision.get(), 2);
    assert_eq!(still_disabled.status, StoredMembershipStatus::Disabled);

    let final_revocation = store
        .transition_member(
            &owner_authz(),
            TransitionMemberCommit {
                user_id: "user-hold-enable-b".into(),
                expected_revision: MembershipRevision::new(1).unwrap(),
                expected_role: MembershipRole::Member,
                expected_status: StoredMembershipStatus::Active,
                role: MembershipRole::Member,
                status: StoredMembershipStatus::Disabled,
            },
        )
        .await
        .unwrap();
    assert_eq!(
        final_revocation.member.status,
        StoredMembershipStatus::Disabled
    );
    let exhausted = store.account_audit_state(&owner_authz()).await.unwrap();
    assert_eq!(exhausted.detailed_rows, 7);
    assert_eq!(exhausted.progress_capacity_remaining, 0);
}

#[tokio::test]
async fn archive_required_blocks_ordinary_mutation_until_matching_checkpoint() {
    let limits = StorageLimits {
        account_audit_detail_rows: 1,
        account_audit_rows_per_account: 3,
        account_audit_rows_global: 3,
        account_audit_progress_rows_per_account: 1,
        account_audit_progress_rows_global: 1,
        account_audit_compaction_batch: 1,
        ..StorageLimits::default()
    };
    let store = SqliteStore::open_with_limits(":memory:", limits)
        .await
        .unwrap();
    bootstrap_test_owner(&store).await;
    let (first_token, _) = member_setup_token_pair();
    store
        .create_member(
            &owner_authz(),
            CreateMemberCommit {
                user_id: "user-archive-first".into(),
                username: "archive-first".into(),
                setup_token: first_token,
            },
        )
        .await
        .unwrap();
    store
        .update_account_audit_policy(
            &owner_authz(),
            UpdateAccountAuditPolicyCommit {
                expected_revision: 1,
                detail_rows: 1,
                legal_hold: false,
                archive_required: true,
            },
        )
        .await
        .unwrap();

    let (blocked_token, _) = member_setup_token_pair();
    assert!(matches!(
        store
            .create_member(
                &owner_authz(),
                CreateMemberCommit {
                    user_id: "user-archive-blocked".into(),
                    username: "archive-blocked".into(),
                    setup_token: blocked_token,
                },
            )
            .await,
        Err(StorageError::AuditArchiveRequired)
    ));
    assert!(matches!(
        store.readiness().await,
        Err(StorageError::AuditArchiveRequired)
    ));
    let page = store
        .list_account_audit_events(&owner_authz(), None, 10)
        .await
        .unwrap();
    let tail = page.items.first().unwrap();
    let checkpointed = store
        .checkpoint_account_audit_archive(
            &owner_authz(),
            AccountAuditCheckpointCommit {
                expected_revision: 1,
                through_sequence: tail.sequence,
                event_hash: tail.event_hash.clone(),
                archive_reference: "archive://account/local/checkpoint-1".into(),
            },
        )
        .await
        .unwrap();
    assert_eq!(checkpointed.archive.through_sequence, tail.sequence);
    assert!(checkpointed.rollup.through_sequence >= 1);
    store.readiness().await.unwrap();

    let (recovered_token, _) = member_setup_token_pair();
    store
        .create_member(
            &owner_authz(),
            CreateMemberCommit {
                user_id: "user-archive-recovered".into(),
                username: "archive-recovered".into(),
                setup_token: recovered_token,
            },
        )
        .await
        .unwrap();
}

#[tokio::test]
async fn account_audit_global_ordinary_capacity_rolls_back_the_cross_account_mutation() {
    let limits = StorageLimits {
        account_audit_detail_rows: 2,
        account_audit_rows_per_account: 3,
        account_audit_rows_global: 4,
        account_audit_progress_rows_per_account: 1,
        account_audit_progress_rows_global: 1,
        account_audit_compaction_batch: 1,
        ..StorageLimits::default()
    };
    let database = TestDatabase::new();
    let store = SqliteStore::open_with_limits(database.path(), limits)
        .await
        .unwrap();
    bootstrap_test_owner(&store).await;
    let secondary = insert_secondary_test_account(database.path());

    for (context, user_id, username) in [
        (owner_authz(), "user-global-local-1", "global-local-1"),
        (secondary.clone(), "user-global-other-1", "global-other-1"),
        (secondary.clone(), "user-global-other-2", "global-other-2"),
    ] {
        let (token, _) = member_setup_token_pair();
        store
            .create_member(
                &context,
                CreateMemberCommit {
                    user_id: user_id.into(),
                    username: username.into(),
                    setup_token: token,
                },
            )
            .await
            .unwrap();
    }
    let (blocked_token, _) = member_setup_token_pair();
    assert!(matches!(
        store
            .create_member(
                &owner_authz(),
                CreateMemberCommit {
                    user_id: "user-global-blocked".into(),
                    username: "global-blocked".into(),
                    setup_token: blocked_token,
                },
            )
            .await,
        Err(StorageError::AuditStorageExhausted)
    ));
    let connection = rusqlite::Connection::open(database.path()).unwrap();
    let atomic_state: (i64, i64, i64) = connection
        .query_row(
            r#"SELECT
                   (SELECT COUNT(*) FROM account_audit_events),
                   (SELECT COUNT(*) FROM users WHERE id = 'user-global-blocked'),
                   (SELECT COUNT(*) FROM member_setup_tokens
                    WHERE user_id = 'user-global-blocked')"#,
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(atomic_state, (3, 0, 0));

    // The saturated secondary account can compact one row on its next
    // admission, proving the global ceiling is recoverable in a small batch.
    let (recovery_token, _) = member_setup_token_pair();
    store
        .create_member(
            &secondary,
            CreateMemberCommit {
                user_id: "user-global-recovered".into(),
                username: "global-recovered".into(),
                setup_token: recovery_token,
            },
        )
        .await
        .unwrap();
    let recovered: (i64, i64) = connection
        .query_row(
            r#"SELECT
                   (SELECT COUNT(*) FROM account_audit_events),
                   (SELECT through_sequence FROM account_audit_rollups
                    WHERE account_id = 'acc_secondary')"#,
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(recovered, (3, 1));
}

#[tokio::test]
async fn account_scope_triggers_and_deep_integrity_reject_missing_or_changed_scope() {
    let database = TestDatabase::new();
    let store = SqliteStore::open(database.path()).await.unwrap();
    store
        .create_session(
            CreateSessionRequest {
                id: "session-account-integrity".into(),
                title: "Account integrity".into(),
            },
            "create-account-integrity",
        )
        .await
        .unwrap();
    let connection = rusqlite::Connection::open(database.path()).unwrap();
    assert!(
        connection
            .execute(
                "INSERT INTO session_runs(session_id, run_id) VALUES ('missing-session', 'missing-run')",
                [],
            )
            .is_err()
    );
    assert!(
        connection
            .execute(
                r#"INSERT INTO incidents(
                       id, title, severity, status, service, region, user_impact, since
                   ) VALUES (
                       'INC-NO-ACCOUNT', 'No account', 'low', 'investigating',
                       'test', 'local', 'none', '2026-08-27T00:00:00.000Z'
                   )"#,
                [],
            )
            .is_err()
    );
    assert!(
        connection
            .execute(
                "UPDATE sessions SET account_id = NULL WHERE id = 'session-account-integrity'",
                [],
            )
            .is_err()
    );

    let trigger_sql: String = connection
        .query_row(
            r#"SELECT sql FROM sqlite_schema
               WHERE type = 'trigger' AND name = 'sessions_account_is_immutable'"#,
            [],
            |row| row.get(0),
        )
        .unwrap();
    connection
        .execute_batch("DROP TRIGGER sessions_account_is_immutable;")
        .unwrap();
    assert_eq!(
        connection
            .execute(
                "UPDATE sessions SET account_id = NULL WHERE id = 'session-account-integrity'",
                [],
            )
            .unwrap(),
        1
    );
    connection.execute_batch(&trigger_sql).unwrap();
    drop(connection);

    assert!(matches!(
        store.verify_integrity().await,
        Err(StorageError::CorruptData(message)) if message.contains("account boundary")
    ));
}

#[tokio::test]
async fn bootstrap_audit_capacity_rolls_terminal_prefixes_without_blocking_rotation() {
    let database = TestDatabase::new();
    let limits = StorageLimits {
        bootstrap_audit_rows: 2,
        ..StorageLimits::default()
    };
    let store = SqliteStore::open_with_limits(database.path(), limits)
        .await
        .unwrap();
    let expiry = (chrono::Utc::now() + chrono::Duration::hours(1))
        .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);

    for index in 1..=140 {
        store
            .replace_bootstrap_token(&bootstrap_token_hash(index), &expiry)
            .await
            .unwrap();
        let detailed_count: i64 = rusqlite::Connection::open(database.path())
            .unwrap()
            .query_row("SELECT COUNT(*) FROM bootstrap_tokens", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert!(detailed_count <= 2);
    }

    let (through_sequence, digest) = bootstrap_audit_rollup(database.path());
    assert_eq!(through_sequence, 138);
    assert_ne!(digest, "0".repeat(64));
    let details = bootstrap_audit_details(database.path());
    assert_eq!(details.len(), 2);
    assert_eq!(details[0].0, 139);
    assert_eq!(details[0].3.as_deref(), Some("superseded"));
    assert_eq!(details[1].0, 140);
    assert_eq!(details[1].2, None);
    assert_eq!(details[1].3, None);
    store.verify_integrity().await.unwrap();
}

#[tokio::test]
async fn bootstrap_audit_rollup_uses_the_versioned_canonical_sha256_chain() {
    let database = TestDatabase::new();
    let limits = StorageLimits {
        bootstrap_audit_rows: 1,
        ..StorageLimits::default()
    };
    let store = SqliteStore::open_with_limits(database.path(), limits)
        .await
        .unwrap();
    let connection = rusqlite::Connection::open(database.path()).unwrap();
    connection
        .execute(
            r#"INSERT INTO bootstrap_tokens(
                   token_hash, created_at, expires_at, terminal_at, terminal_reason
               ) VALUES (?1, ?2, ?3, NULL, NULL)"#,
            params![
                bootstrap_token_hash(1),
                "2026-08-27T00:00:00.000Z",
                "2026-08-27T01:00:00.000Z"
            ],
        )
        .unwrap();
    connection
        .execute(
            r#"UPDATE bootstrap_tokens
               SET terminal_at = ?1, terminal_reason = 'superseded'
               WHERE sequence = 1"#,
            ["2026-08-27T00:30:00.000Z"],
        )
        .unwrap();
    drop(connection);

    store
        .replace_bootstrap_token(&bootstrap_token_hash(2), "2999-01-01T00:00:00.000Z")
        .await
        .unwrap();
    assert_eq!(
        bootstrap_audit_rollup(database.path()),
        (
            1,
            "ac5d61b5346605703a1b0c93dc8192d7b8bad2ecb6482dd0eedfe9f29713dd31".into()
        )
    );
}

#[tokio::test]
async fn bootstrap_audit_rotation_compacts_multiple_sixty_four_row_batches() {
    let database = TestDatabase::new();
    let limits = StorageLimits {
        bootstrap_audit_rows: 1,
        ..StorageLimits::default()
    };
    let store = SqliteStore::open_with_limits(database.path(), limits)
        .await
        .unwrap();
    let connection = rusqlite::Connection::open(database.path()).unwrap();
    for index in 1..=131 {
        connection
            .execute(
                r#"INSERT INTO bootstrap_tokens(
                       token_hash, created_at, expires_at,
                       terminal_at, terminal_reason
                   ) VALUES (?1, ?2, ?3, NULL, NULL)"#,
                params![
                    bootstrap_token_hash(index),
                    "2026-08-26T00:00:00.000Z",
                    "2999-01-01T00:00:00.000Z"
                ],
            )
            .unwrap();
        if index <= 130 {
            connection
                .execute(
                    r#"UPDATE bootstrap_tokens
                       SET terminal_at = ?1, terminal_reason = 'superseded'
                       WHERE sequence = ?2"#,
                    params!["2026-08-26T00:30:00.000Z", i64::try_from(index).unwrap()],
                )
                .unwrap();
        }
    }
    drop(connection);

    store
        .replace_bootstrap_token(&bootstrap_token_hash(10_000), "2999-01-01T00:00:00.000Z")
        .await
        .unwrap();

    let (through_sequence, digest) = bootstrap_audit_rollup(database.path());
    assert_eq!(through_sequence, 131);
    assert_ne!(digest, "0".repeat(64));
    let details = bootstrap_audit_details(database.path());
    assert_eq!(details.len(), 1);
    assert_eq!(details[0].0, 132);
    assert_eq!(details[0].1, bootstrap_token_hash(10_000));
    assert_eq!(details[0].2, None);
    store.verify_integrity().await.unwrap();
}

#[tokio::test]
async fn bootstrap_audit_rotation_survives_wall_clock_rollback() {
    let database = TestDatabase::new();
    let limits = StorageLimits {
        bootstrap_audit_rows: 1,
        ..StorageLimits::default()
    };
    let store = SqliteStore::open_with_limits(database.path(), limits)
        .await
        .unwrap();
    let future = "2999-01-01T00:00:00.000Z";
    let connection = rusqlite::Connection::open(database.path()).unwrap();
    connection
        .execute(
            r#"INSERT INTO bootstrap_tokens(
                   token_hash, created_at, expires_at, terminal_at, terminal_reason
               ) VALUES (?1, ?2, ?3, NULL, NULL)"#,
            params![bootstrap_token_hash(1), "2026-08-27T00:00:00.000Z", future],
        )
        .unwrap();
    connection
        .execute(
            r#"UPDATE bootstrap_tokens
               SET terminal_at = ?1, terminal_reason = 'superseded'
               WHERE sequence = 1"#,
            ["2026-08-27T00:30:00.000Z"],
        )
        .unwrap();
    connection
        .execute(
            r#"INSERT INTO bootstrap_tokens(
                   token_hash, created_at, expires_at, terminal_at, terminal_reason
               ) VALUES (?1, ?2, ?3, NULL, NULL)"#,
            params![bootstrap_token_hash(2), "2026-08-27T00:31:00.000Z", future],
        )
        .unwrap();
    connection
        .execute(
            r#"UPDATE bootstrap_audit_rollup
               SET through_sequence = 1, digest = ?1, updated_at = ?2
               WHERE singleton = 1"#,
            params!["a".repeat(64), future],
        )
        .unwrap();
    connection
        .execute("DELETE FROM bootstrap_tokens WHERE sequence = 1", [])
        .unwrap();
    drop(connection);

    store
        .replace_bootstrap_token(&bootstrap_token_hash(3), future)
        .await
        .unwrap();

    let connection = rusqlite::Connection::open(database.path()).unwrap();
    let (through_sequence, updated_at): (i64, String) = connection
        .query_row(
            r#"SELECT through_sequence, updated_at
               FROM bootstrap_audit_rollup WHERE singleton = 1"#,
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(through_sequence, 2);
    assert_eq!(updated_at, future);
    drop(connection);
    store.verify_integrity().await.unwrap();
}

#[tokio::test]
async fn v11_bootstrap_audit_migration_preserves_rowid_order_across_clock_rollback() {
    let database = TestDatabase::new();
    let initial = SqliteStore::open(database.path()).await.unwrap();
    drop(initial);
    let connection = rusqlite::Connection::open(database.path()).unwrap();
    downgrade_bootstrap_audit_fixture_to_v11(&connection);
    connection
        .execute(
            r#"INSERT INTO bootstrap_tokens(
                   token_hash, created_at, expires_at, used_at
               ) VALUES (?1, ?2, ?3, ?4)"#,
            params![
                bootstrap_token_hash(1),
                "2026-08-27T00:00:00.000Z",
                "2026-08-27T01:00:00.000Z",
                "2026-08-27T00:30:00.000Z"
            ],
        )
        .unwrap();
    connection
        .execute(
            r#"INSERT INTO bootstrap_tokens(
                   token_hash, created_at, expires_at, used_at
               ) VALUES (?1, ?2, ?3, ?4)"#,
            params![
                bootstrap_token_hash(2),
                "2026-08-26T00:00:00.000Z",
                "2026-08-26T01:00:00.000Z",
                "2026-08-26T00:30:00.000Z"
            ],
        )
        .unwrap();
    connection
        .execute(
            r#"INSERT INTO bootstrap_tokens(
                   token_hash, created_at, expires_at, used_at
               ) VALUES (?1, ?2, ?3, NULL)"#,
            params![
                bootstrap_token_hash(3),
                "2026-08-25T00:00:00.000Z",
                "2999-01-01T00:00:00.000Z"
            ],
        )
        .unwrap();
    drop(connection);

    let store = SqliteStore::open(database.path()).await.unwrap();
    let details = bootstrap_audit_details(database.path());
    assert_eq!(
        details.iter().map(|row| row.1.as_str()).collect::<Vec<_>>(),
        vec![
            bootstrap_token_hash(1),
            bootstrap_token_hash(2),
            bootstrap_token_hash(3)
        ]
    );
    store.verify_integrity().await.unwrap();
}

#[tokio::test]
async fn configured_v11_bootstrap_audit_is_compacted_on_open_and_stays_bounded() {
    let database = TestDatabase::new();
    let initial = SqliteStore::open(database.path()).await.unwrap();
    let future = "2999-01-01T00:00:00.000Z";
    let owner_token = bootstrap_token_hash(10_000);
    initial
        .replace_bootstrap_token(&owner_token, future)
        .await
        .unwrap();
    initial
        .bootstrap_owner(BootstrapOwnerCommit {
            bootstrap_token_hash: owner_token,
            auth_session_id: test_owner_auth_session_id(),
            user_id: "user-owner".into(),
            username: "owner".into(),
            password_hash: "$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$ZGlnaWVzdA".into(),
            session_token_hash: "b".repeat(64),
            csrf_hash: "c".repeat(64),
            session_expires_at: future.into(),
        })
        .await
        .unwrap();
    drop(initial);

    let connection = rusqlite::Connection::open(database.path()).unwrap();
    downgrade_bootstrap_audit_fixture_to_v11(&connection);
    for index in 1..=130 {
        connection
            .execute(
                r#"INSERT INTO bootstrap_tokens(
                       token_hash, created_at, expires_at, used_at
                   ) VALUES (?1, '2026-08-26T00:00:00.000Z',
                             '2026-08-26T01:00:00.000Z',
                             '2026-08-26T00:30:00.000Z')"#,
                [bootstrap_token_hash(index)],
            )
            .unwrap();
    }
    drop(connection);

    let limits = StorageLimits {
        bootstrap_audit_rows: 1,
        ..StorageLimits::default()
    };
    let store = SqliteStore::open_with_limits(database.path(), limits.clone())
        .await
        .unwrap();
    let first_rollup = bootstrap_audit_rollup(database.path());
    let first_details = bootstrap_audit_details(database.path());
    assert_eq!(first_rollup.0, 130);
    assert_ne!(first_rollup.1, "0".repeat(64));
    assert_eq!(first_details.len(), 1);
    assert_eq!(first_details[0].0, 131);
    assert_eq!(first_details[0].1, bootstrap_token_hash(130));
    store.verify_integrity().await.unwrap();
    drop(store);

    let reopened = SqliteStore::open_with_limits(database.path(), limits)
        .await
        .unwrap();
    assert_eq!(bootstrap_audit_rollup(database.path()), first_rollup);
    assert_eq!(bootstrap_audit_details(database.path()), first_details);
    reopened.verify_integrity().await.unwrap();
}

#[tokio::test]
async fn current_bootstrap_audit_retention_checks_physical_capacity_before_compaction() {
    let database = TestDatabase::new();
    let future = "2999-01-01T00:00:00.000Z";
    {
        let store = SqliteStore::open(database.path()).await.unwrap();
        for index in 1..=3 {
            store
                .replace_bootstrap_token(&bootstrap_token_hash(index), future)
                .await
                .unwrap();
        }
    }
    let before_rollup = bootstrap_audit_rollup(database.path());
    let before_details = bootstrap_audit_details(database.path());
    assert_eq!(before_rollup, (0, "0".repeat(64)));
    assert_eq!(before_details.len(), 3);

    let limits = StorageLimits {
        bootstrap_audit_rows: 1,
        ..StorageLimits::default()
    };
    let physical_limits = admission_exhausted_physical_limits(database.path());
    assert!(matches!(
        SqliteStore::open_with_limits_and_physical(database.path(), limits, physical_limits).await,
        Err(StorageError::PhysicalStorageExhausted)
    ));
    assert_eq!(bootstrap_audit_rollup(database.path()), before_rollup);
    assert_eq!(bootstrap_audit_details(database.path()), before_details);
}

#[tokio::test]
async fn v11_bootstrap_audit_migration_preserves_unknown_and_records_explicit_reasons() {
    let database = TestDatabase::new();
    let initial = SqliteStore::open(database.path()).await.unwrap();
    drop(initial);
    seed_v11_bootstrap_fixture(database.path(), 1, "2000-01-01T00:00:00.000Z");

    let store = SqliteStore::open(database.path()).await.unwrap();
    let migrated = bootstrap_audit_details(database.path());
    assert_eq!(migrated.len(), 2);
    assert_eq!(migrated[0].3.as_deref(), Some("legacy_unknown"));
    assert_eq!(migrated[1].3, None);

    let future = "2999-01-01T00:00:00.000Z";
    store
        .replace_bootstrap_token(&bootstrap_token_hash(3), future)
        .await
        .unwrap();
    store
        .replace_bootstrap_token(&bootstrap_token_hash(4), future)
        .await
        .unwrap();
    store
        .bootstrap_owner(BootstrapOwnerCommit {
            bootstrap_token_hash: bootstrap_token_hash(4),
            auth_session_id: test_owner_auth_session_id(),
            user_id: "user-owner".into(),
            username: "owner".into(),
            password_hash: "$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$ZGlnaWVzdA".into(),
            session_token_hash: "b".repeat(64),
            csrf_hash: "c".repeat(64),
            session_expires_at: future.into(),
        })
        .await
        .unwrap();

    let reasons = bootstrap_audit_details(database.path())
        .into_iter()
        .map(|row| row.3.unwrap())
        .collect::<Vec<_>>();
    assert_eq!(
        reasons,
        vec!["legacy_unknown", "expired", "superseded", "consumed"]
    );
    store.verify_integrity().await.unwrap();
}

#[tokio::test]
async fn bootstrap_audit_triggers_reject_live_or_uncommitted_delete_and_rollup_rollback() {
    let database = TestDatabase::new();
    let limits = StorageLimits {
        bootstrap_audit_rows: 2,
        ..StorageLimits::default()
    };
    let store = SqliteStore::open_with_limits(database.path(), limits)
        .await
        .unwrap();
    let future = "2999-01-01T00:00:00.000Z";
    for index in 1..=3 {
        store
            .replace_bootstrap_token(&bootstrap_token_hash(index), future)
            .await
            .unwrap();
    }
    let connection = rusqlite::Connection::open(database.path()).unwrap();
    assert!(
        connection
            .execute("DELETE FROM bootstrap_tokens WHERE sequence = 2", [])
            .is_err()
    );
    assert!(
        connection
            .execute("DELETE FROM bootstrap_tokens WHERE sequence = 3", [])
            .is_err()
    );
    assert!(
        connection
            .execute(
                r#"UPDATE bootstrap_tokens
                   SET terminal_reason = 'expired'
                   WHERE sequence = 2"#,
                [],
            )
            .is_err()
    );
    assert!(
        connection
            .execute(
                r#"INSERT INTO bootstrap_tokens(
                       token_hash, created_at, expires_at,
                       terminal_at, terminal_reason
                   ) VALUES (?1, ?2, ?3, ?2, 'expired')"#,
                params![bootstrap_token_hash(99), "2026-08-27T00:00:00.000Z", future],
            )
            .is_err()
    );
    assert!(
        connection
            .execute(
                "UPDATE bootstrap_audit_rollup SET through_sequence = 0 WHERE singleton = 1",
                [],
            )
            .is_err()
    );
    assert!(
        connection
            .execute("DELETE FROM bootstrap_audit_rollup", [])
            .is_err()
    );
    drop(connection);
    store.verify_integrity().await.unwrap();
}

#[tokio::test]
async fn bootstrap_audit_integrity_rejects_a_malformed_rollup_digest() {
    let database = TestDatabase::new();
    let limits = StorageLimits {
        bootstrap_audit_rows: 1,
        ..StorageLimits::default()
    };
    let store = SqliteStore::open_with_limits(database.path(), limits)
        .await
        .unwrap();
    let future = "2999-01-01T00:00:00.000Z";
    store
        .replace_bootstrap_token(&bootstrap_token_hash(1), future)
        .await
        .unwrap();
    store
        .replace_bootstrap_token(&bootstrap_token_hash(2), future)
        .await
        .unwrap();

    force_bootstrap_rollup_digest(database.path(), &"g".repeat(64));
    assert!(matches!(
        store.verify_integrity().await,
        Err(StorageError::CorruptData(message))
            if message.contains("bootstrap audit rollup")
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
                authz: AuthzContext {
                    user_id: "missing-user".into(),
                    auth_session_id: AuthSessionId::from_persistence("asi_missing_user").unwrap(),
                    ..owner_authz()
                },
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
async fn v5_configured_database_migrates_to_the_local_owner_membership() {
    let database = TestDatabase::new();
    create_v5_database_with_owner(database.path());

    let store = SqliteStore::open(database.path()).await.unwrap();
    store.verify_integrity().await.unwrap();
    let connection = rusqlite::Connection::open(database.path()).unwrap();
    let migrated: (i64, String, String, String, String, i64) = connection
        .query_row(
            r#"SELECT
                   (SELECT MAX(version) FROM schema_migrations),
                   (SELECT account_id FROM incidents WHERE id = 'INC-2048'),
                   (SELECT account_id FROM sessions WHERE id = 'session-ZR-1842'),
                   (SELECT account_id FROM runs WHERE id = 'ZR-1842'),
                   (SELECT role FROM account_memberships
                    WHERE account_id = 'acc_local' AND user_id = 'user-v5-owner'),
                   (SELECT revision FROM account_memberships
                    WHERE account_id = 'acc_local' AND user_id = 'user-v5-owner')"#,
            [],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                ))
            },
        )
        .unwrap();
    assert_eq!(
        migrated,
        (
            21,
            "acc_local".into(),
            "acc_local".into(),
            "acc_local".into(),
            "owner".into(),
            1
        )
    );
}

#[tokio::test]
async fn v13_configured_active_work_migrates_with_account_authority_and_exact_volume() {
    let database = TestDatabase::new();
    let store = seeded_file_store(database.path()).await;
    bootstrap_test_owner(&store).await;
    store
        .create_session_for_actor(
            &owner_authz(),
            CreateSessionRequest {
                id: "session-v13-active".into(),
                title: "Active v13 work".into(),
            },
            "create-v13-active",
        )
        .await
        .unwrap();
    store
        .start_turn_and_enqueue_reply_for_actor(
            &owner_authz(),
            "session-v13-active",
            StartTurnRequest {
                turn_id: "turn-v13-active".into(),
                user_message: "Preserve this queued reply".into(),
                expected_sequence: 1,
            },
            "start-v13-active",
            reply_job_spec("reply-v13-active", "turn-v13-active"),
        )
        .await
        .unwrap();
    let (snapshot, _) = seed_fixture();
    store
        .commit_review_for_actor(
            &owner_authz(),
            approved_dispatch_commit(&snapshot, "dispatch-v13-active"),
        )
        .await
        .unwrap();
    drop(store);

    let connection = rusqlite::Connection::open(database.path()).unwrap();
    downgrade_durable_authorization_fixture_to_v13(&connection);
    let v13_counts: (i64, i64, i64, i64) = connection
        .query_row(
            r#"SELECT
                   (SELECT COUNT(*) FROM auth_sessions),
                   (SELECT COUNT(*) FROM reply_jobs),
                   (SELECT COUNT(*) FROM dispatch_jobs),
                   (SELECT COUNT(*) FROM finalization_reservations)"#,
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .unwrap();
    assert_eq!(v13_counts, (1, 1, 1, 2));
    drop(connection);

    let migrated = SqliteStore::open(database.path()).await.unwrap();
    migrated.verify_integrity().await.unwrap();
    let principal = migrated
        .authenticate(&"b".repeat(64))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(principal.authz.account_id, AccountId::local());
    assert_eq!(principal.authz.user_id, "user-owner");
    assert_eq!(principal.authz.membership_role, MembershipRole::Owner);
    assert_eq!(principal.authz.membership_revision.get(), 1);
    assert_eq!(
        migrated
            .reply_job("reply-v13-active")
            .await
            .unwrap()
            .unwrap()
            .status,
        ReplyJobStatus::Queued
    );
    assert_eq!(
        migrated
            .dispatch_job("call-local-001")
            .await
            .unwrap()
            .unwrap()
            .status,
        DispatchStatus::Queued
    );
    let connection = rusqlite::Connection::open(database.path()).unwrap();
    let migrated_counts: (i64, i64, i64, i64, i64) = connection
        .query_row(
            r#"SELECT
                   (SELECT MAX(version) FROM schema_migrations),
                   (SELECT COUNT(*) FROM reply_jobs
                    WHERE account_id = 'acc_local'
                      AND actor_user_id = 'user-owner'
                      AND actor_membership_revision = 1),
                   (SELECT COUNT(*) FROM dispatch_jobs
                    WHERE account_id = 'acc_local'
                      AND initiating_actor_user_id = 'user-owner'
                      AND initiating_membership_revision = 1
                      AND approving_actor_user_id = 'user-owner'
                      AND approving_membership_revision = 1),
                   (SELECT COUNT(*) FROM finalization_reservations
                    WHERE account_id = 'acc_local'
                      AND actor_user_id = 'user-owner'),
                   (SELECT COUNT(*) FROM auth_sessions)"#,
            [],
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
    assert_eq!(migrated_counts, (21, 1, 1, 2, 1));
}

#[tokio::test]
async fn v13_unconfigured_null_authority_migrates_and_only_bootstrap_owner_claims_once() {
    let database = TestDatabase::new();
    create_v7_database_with_legacy_dispatch(database.path());
    let store = SqliteStore::open(database.path()).await.unwrap();
    store
        .create_session(
            CreateSessionRequest {
                id: "session-v13-unconfigured".into(),
                title: "Unconfigured v13 work".into(),
            },
            "create-v13-unconfigured",
        )
        .await
        .unwrap();
    store
        .start_turn(
            "session-v13-unconfigured",
            StartTurnRequest {
                turn_id: "turn-v13-unconfigured".into(),
                user_message: "Preserve prebootstrap capacity".into(),
                expected_sequence: 1,
            },
            "start-v13-unconfigured",
        )
        .await
        .unwrap();
    drop(store);

    let connection = rusqlite::Connection::open(database.path()).unwrap();
    downgrade_durable_authorization_fixture_to_v13(&connection);
    assert_eq!(
        connection
            .query_row("SELECT MAX(version) FROM schema_migrations", [], |row| {
                row.get::<_, i64>(0)
            })
            .unwrap(),
        13
    );
    assert_eq!(
        connection
            .query_row(
                "SELECT COUNT(*) FROM finalization_reservations WHERE scope_id = '__legacy__'",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        2
    );
    drop(connection);

    let migrated = SqliteStore::open(database.path()).await.unwrap();
    migrated.verify_integrity().await.unwrap();
    let connection = rusqlite::Connection::open(database.path()).unwrap();
    let unclaimed: (i64, i64, i64, i64) = connection
        .query_row(
            r#"SELECT
                   (SELECT COUNT(*) FROM session_command_receipts
                    WHERE actor_user_id IS NULL),
                   (SELECT COUNT(*) FROM dispatch_jobs
                    WHERE initiating_actor_user_id IS NULL
                      AND initiating_membership_revision IS NULL
                      AND approving_actor_user_id IS NULL
                      AND approving_membership_revision IS NULL),
                   (SELECT COUNT(*) FROM finalization_reservations
                    WHERE actor_user_id IS NULL),
                   (SELECT COUNT(*) FROM auth_sessions)"#,
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .unwrap();
    assert_eq!(unclaimed, (2, 1, 2, 0));
    drop(connection);

    bootstrap_test_owner(&migrated).await;
    let connection = rusqlite::Connection::open(database.path()).unwrap();
    let claimed: (i64, i64, i64) = connection
        .query_row(
            r#"SELECT
                   (SELECT COUNT(*) FROM session_command_receipts
                    WHERE actor_user_id = 'user-owner'),
                   (SELECT COUNT(*) FROM dispatch_jobs
                    WHERE initiating_actor_user_id IS NULL
                      AND initiating_membership_revision IS NULL
                      AND approving_actor_user_id = 'user-owner'
                      AND approving_membership_revision = 1),
                   (SELECT COUNT(*) FROM finalization_reservations
                    WHERE actor_user_id = 'user-owner')"#,
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(claimed, (2, 1, 2));
    assert!(
        connection
            .execute(
                "UPDATE session_command_receipts SET actor_user_id = NULL",
                [],
            )
            .is_err()
    );
    assert!(
        connection
            .execute(
                "UPDATE dispatch_jobs SET approving_actor_user_id = NULL",
                [],
            )
            .is_err()
    );
    assert!(
        connection
            .execute(
                "UPDATE finalization_reservations SET actor_user_id = NULL",
                [],
            )
            .is_err()
    );
}

#[tokio::test]
async fn v13_auth_migration_retains_only_the_active_local_owner_session() {
    let database = TestDatabase::new();
    let store = SqliteStore::open(database.path()).await.unwrap();
    bootstrap_test_owner(&store).await;
    insert_test_member(database.path(), "user-member", "member");
    activate_test_member_auth(database.path(), "user-member", "asi_test_member");
    drop(store);

    let connection = rusqlite::Connection::open(database.path()).unwrap();
    downgrade_durable_authorization_fixture_to_v13(&connection);
    assert_eq!(
        connection
            .query_row("SELECT COUNT(*) FROM auth_sessions", [], |row| {
                row.get::<_, i64>(0)
            })
            .unwrap(),
        2
    );
    drop(connection);

    let migrated = SqliteStore::open(database.path()).await.unwrap();
    assert!(
        migrated
            .authenticate(&"b".repeat(64))
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        migrated
            .authenticate(&"e".repeat(64))
            .await
            .unwrap()
            .is_none()
    );
    let connection = rusqlite::Connection::open(database.path()).unwrap();
    assert_eq!(
        connection
            .query_row(
                r#"SELECT COUNT(*) FROM auth_sessions session
                   JOIN account_memberships membership
                     ON membership.account_id = session.account_id
                    AND membership.user_id = session.user_id
                   WHERE session.account_id = 'acc_local'
                     AND session.membership_revision = membership.revision
                     AND membership.role = 'owner'
                     AND membership.status = 'active'"#,
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        1
    );
    drop(connection);
}

#[tokio::test]
async fn v14_preflight_failure_rolls_back_to_an_intact_v13_schema() {
    let database = TestDatabase::new();
    let store = SqliteStore::open(database.path()).await.unwrap();
    bootstrap_test_owner(&store).await;
    drop(store);
    let connection = rusqlite::Connection::open(database.path()).unwrap();
    downgrade_durable_authorization_fixture_to_v13(&connection);
    connection
        .execute(
            r#"INSERT INTO accounts(id, name, status, created_at, updated_at)
               VALUES (
                   'acc_unexpected', 'Unexpected', 'active',
                   '2026-08-27T00:00:00.000Z', '2026-08-27T00:00:00.000Z'
               )"#,
            [],
        )
        .unwrap();
    connection
        .execute(
            r#"INSERT INTO account_memberships(
                   account_id, user_id, role, status, revision,
                   created_at, updated_at
               ) VALUES (
                   'acc_unexpected', 'user-owner', 'owner', 'active', 1,
                   '2026-08-27T00:00:00.000Z', '2026-08-27T00:00:00.000Z'
               )"#,
            [],
        )
        .unwrap();
    drop(connection);

    assert!(SqliteStore::open(database.path()).await.is_err());
    let connection = rusqlite::Connection::open(database.path()).unwrap();
    let rollback_state: (i64, i64, i64, i64) = connection
        .query_row(
            r#"SELECT
                   (SELECT MAX(version) FROM schema_migrations),
                   (SELECT COUNT(*) FROM pragma_table_info('auth_sessions')
                    WHERE name IN ('id', 'account_id', 'membership_revision')),
                   (SELECT COUNT(*) FROM sqlite_schema
                    WHERE name LIKE '%_v13' OR name LIKE '%_v14'),
                   (SELECT COUNT(*) FROM sqlite_schema
                    WHERE type = 'trigger'
                      AND name = 'auth_sessions_require_current_membership')"#,
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .unwrap();
    assert_eq!(rollback_state, (13, 0, 0, 0));
    assert_eq!(
        connection
            .query_row("SELECT COUNT(*) FROM auth_sessions", [], |row| {
                row.get::<_, i64>(0)
            })
            .unwrap(),
        1
    );
}

#[tokio::test]
async fn v14_rejects_a_disabled_legacy_owner_before_committing_any_schema_change() {
    let database = TestDatabase::new();
    let store = SqliteStore::open(database.path()).await.unwrap();
    bootstrap_test_owner(&store).await;
    drop(store);
    let connection = rusqlite::Connection::open(database.path()).unwrap();
    downgrade_durable_authorization_fixture_to_v13(&connection);
    connection
        .execute(
            r#"UPDATE users
               SET status = 'disabled', updated_at = '2999-01-01T00:00:00.000Z'
               WHERE id = 'user-owner'"#,
            [],
        )
        .unwrap();
    drop(connection);

    assert!(SqliteStore::open(database.path()).await.is_err());
    let connection = rusqlite::Connection::open(database.path()).unwrap();
    let rollback_state: (i64, i64, i64) = connection
        .query_row(
            r#"SELECT
                   (SELECT MAX(version) FROM schema_migrations),
                   (SELECT COUNT(*) FROM pragma_table_info('auth_sessions')
                    WHERE name IN ('id', 'account_id', 'membership_revision')),
                   (SELECT COUNT(*) FROM sqlite_schema
                    WHERE name LIKE '%_v13' OR name LIKE '%_v14')"#,
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(rollback_state, (13, 0, 0));
    assert_eq!(
        connection
            .query_row("SELECT COUNT(*) FROM auth_sessions", [], |row| {
                row.get::<_, i64>(0)
            })
            .unwrap(),
        1
    );
}

#[tokio::test]
async fn v14_database_migrates_through_v19_with_member_and_audit_roots() {
    let database = TestDatabase::new();
    let store = SqliteStore::open(database.path()).await.unwrap();
    bootstrap_test_owner(&store).await;
    drop(store);
    let connection = rusqlite::Connection::open(database.path()).unwrap();
    downgrade_member_lifecycle_fixture_to_v14(&connection);
    assert_eq!(
        connection
            .query_row("SELECT MAX(version) FROM schema_migrations", [], |row| {
                row.get::<_, i64>(0)
            })
            .unwrap(),
        14
    );
    assert_eq!(
        connection
            .query_row(
                r#"SELECT COUNT(*) FROM sqlite_schema
                   WHERE name IN (
                       'member_setup_tokens', 'account_audit_rollups',
                       'account_audit_policies', 'account_audit_archive_state',
                       'account_audit_events'
                   )"#,
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        0
    );
    drop(connection);

    let migrated = SqliteStore::open(database.path()).await.unwrap();
    migrated.readiness().await.unwrap();
    assert!(
        migrated
            .authenticate(&"b".repeat(64))
            .await
            .unwrap()
            .is_some()
    );
    let connection = rusqlite::Connection::open(database.path()).unwrap();
    let state: (i64, i64, i64, i64, i64) = connection
        .query_row(
            r#"SELECT
                   (SELECT MAX(version) FROM schema_migrations),
                   (SELECT COUNT(*) FROM account_audit_rollups),
                   (SELECT COUNT(*) FROM account_audit_policies),
                   (SELECT COUNT(*) FROM account_audit_archive_state),
                   (SELECT COUNT(*) FROM sqlite_schema
                    WHERE name IN (
                        'member_setup_tokens', 'account_audit_rollups',
                        'account_audit_policies', 'account_audit_archive_state',
                        'account_audit_events', 'member_setup_tokens_expiry_idx',
                        'account_audit_events_hash_idx', 'account_audit_events_time_idx',
                        'member_setup_tokens_require_pending_member',
                        'member_setup_tokens_reject_update',
                        'account_audit_events_require_chain',
                        'account_audit_events_reject_update',
                        'account_audit_events_require_rollup_before_delete',
                        'account_audit_rollups_enforce_forward_update',
                        'account_audit_rollups_reject_delete',
                        'account_audit_policies_enforce_revision',
                        'account_audit_policies_reject_delete',
                        'account_audit_archive_state_enforce_revision',
                        'account_audit_archive_state_reject_delete'
                    ))"#,
            [],
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
    assert_eq!(state, (21, 1, 1, 1, 19));
}

#[tokio::test]
async fn v15_migration_seeds_the_configured_audit_detail_limit() {
    let database = TestDatabase::new();
    let store = SqliteStore::open(database.path()).await.unwrap();
    bootstrap_test_owner(&store).await;
    drop(store);
    let connection = rusqlite::Connection::open(database.path()).unwrap();
    downgrade_member_lifecycle_fixture_to_v14(&connection);
    drop(connection);

    let limits = StorageLimits {
        account_audit_detail_rows: 2,
        account_audit_rows_per_account: 4,
        account_audit_rows_global: 4,
        account_audit_progress_rows_per_account: 1,
        account_audit_progress_rows_global: 1,
        account_audit_compaction_batch: 1,
        ..StorageLimits::default()
    };
    let migrated = SqliteStore::open_with_limits(database.path(), limits)
        .await
        .unwrap();
    migrated.readiness().await.unwrap();
    drop(migrated);

    let connection = rusqlite::Connection::open(database.path()).unwrap();
    let state: (i64, i64) = connection
        .query_row(
            r#"SELECT
                   (SELECT MAX(version) FROM schema_migrations),
                   (SELECT detail_rows FROM account_audit_policies
                    WHERE account_id = 'acc_local')"#,
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(state, (21, 2));
}

#[tokio::test]
async fn v15_reopen_rejects_a_lower_audit_detail_limit_without_mutating_policy() {
    let database = TestDatabase::new();
    let original_limits = StorageLimits {
        account_audit_detail_rows: 4,
        account_audit_rows_per_account: 6,
        account_audit_rows_global: 6,
        account_audit_progress_rows_per_account: 1,
        account_audit_progress_rows_global: 1,
        account_audit_compaction_batch: 1,
        ..StorageLimits::default()
    };
    let store = SqliteStore::open_with_limits(database.path(), original_limits.clone())
        .await
        .unwrap();
    bootstrap_test_owner(&store).await;
    drop(store);

    let lower_limits = StorageLimits {
        account_audit_detail_rows: 2,
        ..original_limits.clone()
    };
    assert!(matches!(
        SqliteStore::open_with_limits(database.path(), lower_limits).await,
        Err(StorageError::AccountAuditPolicyExceedsConfiguredLimit {
            account_id,
            detail_rows: 4,
            configured_limit: 2,
        }) if account_id == "acc_local"
    ));

    let connection = rusqlite::Connection::open(database.path()).unwrap();
    let state: (i64, i64) = connection
        .query_row(
            r#"SELECT
                   (SELECT MAX(version) FROM schema_migrations),
                   (SELECT detail_rows FROM account_audit_policies
                    WHERE account_id = 'acc_local')"#,
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(state, (21, 4));
    drop(connection);

    let reopened = SqliteStore::open_with_limits(database.path(), original_limits)
        .await
        .unwrap();
    reopened.readiness().await.unwrap();
}

#[tokio::test]
async fn v15_migration_failure_rolls_back_dispatch_rebuild_and_schema_version() {
    let database = TestDatabase::new();
    drop(SqliteStore::open(database.path()).await.unwrap());
    let connection = rusqlite::Connection::open(database.path()).unwrap();
    downgrade_member_lifecycle_fixture_to_v14(&connection);
    let dispatch_v14_sql: String = connection
        .query_row(
            "SELECT sql FROM sqlite_schema WHERE type = 'table' AND name = 'dispatch_jobs'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    connection
        .execute_batch(
            r#"CREATE TABLE account_audit_rollups(
                   injected INTEGER PRIMARY KEY
               ) STRICT;"#,
        )
        .unwrap();
    drop(connection);

    assert!(SqliteStore::open(database.path()).await.is_err());
    let connection = rusqlite::Connection::open(database.path()).unwrap();
    let rollback_state: (i64, i64, i64, String, String) = connection
        .query_row(
            r#"SELECT
                   (SELECT MAX(version) FROM schema_migrations),
                   (SELECT COUNT(*) FROM sqlite_schema
                    WHERE name = 'member_setup_tokens'),
                   (SELECT COUNT(*) FROM sqlite_schema
                    WHERE name LIKE '%_v14_provenance'),
                   (SELECT sql FROM sqlite_schema
                    WHERE type = 'table' AND name = 'dispatch_jobs'),
                   (SELECT "table" FROM pragma_foreign_key_list('finalization_reservations')
                    WHERE "from" = 'call_id')"#,
            [],
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
    assert_eq!(rollback_state.0, 14);
    assert_eq!(rollback_state.1, 0);
    assert_eq!(rollback_state.2, 0);
    assert_eq!(rollback_state.3, dispatch_v14_sql);
    assert_eq!(rollback_state.4, "dispatch_jobs");
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
        open_turns_per_actor: TOTAL,
        open_turns_per_account: TOTAL,
        open_turns_global: TOTAL,
        active_reply_jobs_per_actor: TOTAL,
        active_reply_jobs_per_account: TOTAL,
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
                &owner_authz(),
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
                &owner_authz(),
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
    let store = operation_limited_store(database.path(), test_operation_limits(9, 1)).await;
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
        .start_turn_and_enqueue_reply_for_actor(
            &owner_authz(),
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
    let legacy_request_json = json!({
        "messages": [{
            "role": "user",
            "content": &request.user_message,
        }],
    });
    let legacy_fingerprint = serde_json::to_string(&json!({
        "session_id": "session-alpha",
        "request": &request,
        "reply_job": {
            "id": &spec.id,
            "provider_name": &spec.provider_name,
            "model_name": &spec.model_name,
            "request_json": legacy_request_json,
        },
    }))
    .unwrap();
    let connection = rusqlite::Connection::open(database.path()).unwrap();
    let immutable_trigger: String = connection
        .query_row(
            r#"SELECT sql FROM sqlite_schema
               WHERE type = 'trigger' AND name = 'session_command_receipts_reject_update'"#,
            [],
            |row| row.get(0),
        )
        .unwrap();
    connection
        .execute_batch("DROP TRIGGER session_command_receipts_reject_update;")
        .unwrap();
    connection
        .execute(
            r#"UPDATE session_command_receipts
               SET request_fingerprint = ?1
               WHERE operation = 'start_turn' AND idempotency_key = 'reply-start-atomic'"#,
            [legacy_fingerprint],
        )
        .unwrap();
    connection.execute_batch(&immutable_trigger).unwrap();
    drop(connection);

    let rotated_authz = owner_authz_with_session("asi_rotated_owner");
    let expiry = (chrono::Utc::now() + chrono::Duration::hours(1))
        .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    store
        .create_auth_session(AuthSessionCommit {
            authz: rotated_authz.clone(),
            session_token_hash: "9".repeat(64),
            csrf_hash: "8".repeat(64),
            expires_at: expiry,
        })
        .await
        .unwrap();
    let mut rotated_spec = spec.clone();
    rotated_spec.authz = rotated_authz.clone();
    rotated_spec.request_json = json!({
        "messages": [
            {"role": "user", "content": "server context may evolve"},
            {"role": "assistant", "content": "the stored job stays authoritative"},
            {"role": "user", "content": "retry the same client command"}
        ]
    });
    let replay = store
        .start_turn_and_enqueue_reply_for_actor(
            &rotated_authz,
            "session-alpha",
            request,
            "reply-start-atomic",
            rotated_spec,
        )
        .await
        .unwrap();
    assert!(replay.start.replayed);
    assert_eq!(replay.job, enqueued.job);

    let connection = rusqlite::Connection::open(database.path()).unwrap();
    let actor_user_id: String = connection
        .query_row(
            r#"SELECT actor_user_id FROM session_command_receipts
               WHERE operation = 'start_turn' AND idempotency_key = 'reply-start-atomic'"#,
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(actor_user_id, "user-owner");
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
async fn v19_agent_manifest_is_canonical_actor_scoped_reused_and_secret_free() {
    let database = TestDatabase::new();
    let store = created_owned_file_session_store(database.path()).await;
    let manifest = test_agent_manifest();
    let first = store
        .start_turn_and_enqueue_agent_for_actor(
            &owner_authz(),
            "session-alpha",
            StartTurnRequest {
                turn_id: "turn-manifest-first".into(),
                user_message: "Use the exact deployment manifest".into(),
                expected_sequence: 1,
            },
            "turn-manifest-first-start",
            agent_turn_spec_with_manifest(
                "agent-manifest-first",
                "turn-manifest-first",
                manifest.clone(),
            ),
        )
        .await
        .unwrap();
    assert_eq!(
        first.agent.deployment_manifest_digest.as_deref(),
        Some(manifest.digest.as_str())
    );
    assert_eq!(
        store
            .agent_deployment_manifest_for_actor(
                &owner_authz(),
                "session-alpha",
                "turn-manifest-first",
            )
            .await
            .unwrap(),
        Some(manifest.clone())
    );
    assert!(matches!(
        store
            .agent_deployment_manifest_for_actor(
                &foreign_authz(),
                "session-alpha",
                "turn-manifest-first",
            )
            .await,
        Err(StorageError::AuthSessionNotFound)
    ));

    let AgentModelClaimOutcome::Claimed(job) =
        store.claim_next_agent_model(&manifest).await.unwrap()
    else {
        panic!("the exact deployment manifest must authorize the model claim");
    };
    let AgentModelCompletion::Final(first_completion) = store
        .complete_agent_model_success(AgentModelSuccessCommit {
            job_id: job.id,
            response_json: agent_final_response_json("manifest-bound reply"),
            resolution: AgentModelResolution::Final {
                assistant_message: "manifest-bound reply".into(),
                provenance: agent_model_provenance(),
            },
        })
        .await
        .unwrap()
    else {
        panic!("the manifest-bound model should complete normally");
    };
    store
        .start_turn_and_enqueue_agent_for_actor(
            &owner_authz(),
            "session-alpha",
            StartTurnRequest {
                turn_id: "turn-manifest-second".into(),
                user_message: "Reuse the same immutable manifest".into(),
                expected_sequence: first_completion.session.sequence,
            },
            "turn-manifest-second-start",
            agent_turn_spec_with_manifest(
                "agent-manifest-second",
                "turn-manifest-second",
                manifest.clone(),
            ),
        )
        .await
        .unwrap();
    store.verify_integrity().await.unwrap();

    let connection = rusqlite::Connection::open(database.path()).unwrap();
    let version: i64 = connection
        .query_row("SELECT MAX(version) FROM schema_migrations", [], |row| {
            row.get(0)
        })
        .unwrap();
    let manifest_rows: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM agent_deployment_manifests",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let (schema_version, envelope_json): (i64, String) = connection
        .query_row(
            r#"SELECT schema_version, envelope_json
               FROM agent_deployment_manifests WHERE digest = ?1"#,
            [&manifest.digest],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(version, 21);
    assert_eq!(
        manifest_rows, 1,
        "the identical manifest must be deduplicated"
    );
    assert_eq!(schema_version, i64::from(manifest.schema_version));
    assert_eq!(
        envelope_json.as_bytes(),
        manifest.canonical_json_bytes().unwrap().as_slice()
    );
    assert!(!contains_forbidden_manifest_key(
        &serde_json::from_str(&envelope_json).unwrap()
    ));
    let columns = connection
        .prepare("SELECT name FROM pragma_table_info('agent_deployment_manifests') ORDER BY cid")
        .unwrap()
        .query_map([], |row| row.get::<_, String>(0))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(
        columns,
        ["digest", "schema_version", "envelope_json", "created_at"]
    );
    assert!(
        connection
            .execute(
                "UPDATE agent_deployment_manifests SET created_at = created_at WHERE digest = ?1",
                [&manifest.digest],
            )
            .is_err()
    );
    assert!(
        connection
            .execute(
                "DELETE FROM agent_deployment_manifests WHERE digest = ?1",
                [&manifest.digest],
            )
            .is_err()
    );
}

#[tokio::test]
async fn agent_run_epoch_and_execution_facts_commit_with_model_lifecycle() {
    let database = TestDatabase::new();
    let store = created_owned_file_session_store(database.path()).await;
    let manifest = test_agent_manifest();
    let enqueued = store
        .start_turn_and_enqueue_agent_for_actor(
            &owner_authz(),
            "session-alpha",
            StartTurnRequest {
                turn_id: "turn-execution-ledger".into(),
                user_message: "Record the exact execution authority".into(),
                expected_sequence: 1,
            },
            "execution-ledger-start",
            agent_turn_spec_with_manifest(
                "agent-execution-ledger",
                "turn-execution-ledger",
                manifest.clone(),
            ),
        )
        .await
        .unwrap();

    let connection = rusqlite::Connection::open(database.path()).unwrap();
    let admitted: (i64, i64, String, String) = connection
        .query_row(
            r#"SELECT head.head_sequence, head.projected_agent_revision,
                      head.history_origin, event.fact_kind
               FROM agent_execution_heads head
               JOIN agent_execution_events event
                 ON event.agent_id = head.agent_id AND event.sequence = 1
               WHERE head.agent_id = ?1"#,
            [&enqueued.agent.id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .unwrap();
    assert_eq!(admitted, (1, 1, "native".into(), "agent_admitted".into()));
    let epoch_count: i64 = connection
        .query_row("SELECT COUNT(*) FROM agent_run_epochs", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(
        epoch_count, 0,
        "queued work has not crossed the release checkpoint"
    );
    drop(connection);

    let admitted_explain = store
        .agent_execution_explain_for_actor(&owner_authz(), "session-alpha", "turn-execution-ledger")
        .await
        .unwrap();
    assert_eq!(admitted_explain.agent.revision, 1);
    assert_eq!(admitted_explain.watermark.fact_head_sequence, 1);
    assert!(admitted_explain.epochs.is_empty());
    assert_eq!(admitted_explain.facts.len(), 1);
    assert_eq!(
        admitted_explain.history.overall,
        execution::ReconstructionLevel::Complete
    );
    assert!(matches!(
        store
            .agent_execution_explain_for_actor(
                &foreign_authz(),
                "session-alpha",
                "turn-execution-ledger",
            )
            .await,
        Err(StorageError::AuthSessionNotFound)
    ));
    assert!(matches!(
        store
            .agent_run_epoch_explain_for_actor(
                &owner_authz(),
                "session-alpha",
                "turn-execution-ledger",
                1,
            )
            .await,
        Err(StorageError::AgentModelJobNotFound(_))
    ));

    let AgentModelClaimOutcome::Claimed(job) =
        store.claim_next_agent_model(&manifest).await.unwrap()
    else {
        panic!("the model job must cross one durable release checkpoint");
    };
    let connection = rusqlite::Connection::open(database.path()).unwrap();
    let (epoch_json, fact_json, head_sequence): (String, String, i64) = connection
        .query_row(
            r#"SELECT epoch.envelope_json, event.envelope_json, head.head_sequence
               FROM agent_run_epochs epoch
               JOIN agent_execution_events event
                 ON event.agent_id = epoch.agent_id
                AND event.epoch_digest = epoch.digest
               JOIN agent_execution_heads head ON head.agent_id = epoch.agent_id
               WHERE epoch.model_job_id = ?1"#,
            [&job.id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    let epoch = execution::RunEpochEnvelope::from_json_slice(epoch_json.as_bytes()).unwrap();
    let fact = execution::ExecutionFactEnvelope::from_json_slice(fact_json.as_bytes()).unwrap();
    assert_eq!(head_sequence, 2);
    assert_eq!(
        epoch.epoch.bound_manifest_digest.as_ref().unwrap().as_str(),
        manifest.digest
    );
    assert_eq!(
        epoch.epoch.observed_manifest_digest.as_str(),
        manifest.digest
    );
    assert_eq!(fact.fact.sequence, 2);
    assert_eq!(
        fact.fact.previous_fact_digest.as_ref().unwrap().as_str(),
        connection
            .query_row(
                r#"SELECT fact_digest FROM agent_execution_events
                   WHERE agent_id = ?1 AND sequence = 1"#,
                [&enqueued.agent.id],
                |row| row.get::<_, String>(0),
            )
            .unwrap()
    );
    assert!(!epoch_json.contains("Record the exact execution authority"));
    drop(connection);

    let started_explain = store
        .agent_run_epoch_explain_for_actor(
            &owner_authz(),
            "session-alpha",
            "turn-execution-ledger",
            1,
        )
        .await
        .unwrap();
    assert_eq!(started_explain.request.value, enqueued.job.request_json);
    assert_eq!(
        started_explain.epoch.status,
        execution::EpochExecutionStatus::Started
    );
    assert_eq!(
        started_explain.outcome,
        execution::EpochOutcomeMaterial::Pending
    );
    assert_eq!(started_explain.facts.len(), 2);
    assert!(
        started_explain
            .history
            .reasons
            .contains(&execution::ExecutionHistoryReason::OutcomePending)
    );

    store
        .complete_agent_model_success(AgentModelSuccessCommit {
            job_id: job.id,
            response_json: agent_final_response_json("Execution is recorded."),
            resolution: AgentModelResolution::Final {
                assistant_message: "Execution is recorded.".into(),
                provenance: agent_model_provenance(),
            },
        })
        .await
        .unwrap();
    store.verify_integrity().await.unwrap();
    let connection = rusqlite::Connection::open(database.path()).unwrap();
    let (head_sequence, event_count, epoch_count): (i64, i64, i64) = connection
        .query_row(
            r#"SELECT
                   (SELECT head_sequence FROM agent_execution_heads
                    WHERE agent_id = ?1),
                   (SELECT COUNT(*) FROM agent_execution_events WHERE agent_id = ?1),
                   (SELECT COUNT(*) FROM agent_run_epochs WHERE agent_id = ?1)"#,
            [&enqueued.agent.id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!((head_sequence, event_count, epoch_count), (3, 3, 1));

    let completed_explain = store
        .agent_execution_explain_for_actor(&owner_authz(), "session-alpha", "turn-execution-ledger")
        .await
        .unwrap();
    assert_eq!(completed_explain.watermark.fact_head_sequence, 3);
    assert_eq!(completed_explain.epochs.len(), 1);
    assert_eq!(
        completed_explain.epochs[0].status,
        execution::EpochExecutionStatus::Succeeded
    );
    assert_eq!(
        completed_explain.history.overall,
        execution::ReconstructionLevel::Complete
    );
    let completed_epoch = store
        .agent_run_epoch_explain_for_actor(
            &owner_authz(),
            "session-alpha",
            "turn-execution-ledger",
            1,
        )
        .await
        .unwrap();
    assert_eq!(completed_epoch.request.value, enqueued.job.request_json);
    let execution::EpochOutcomeMaterial::Succeeded {
        response,
        provenance,
    } = completed_epoch.outcome
    else {
        panic!("the completed model epoch must expose its persisted response");
    };
    assert_eq!(
        response.value,
        agent_final_response_json("Execution is recorded.")
    );
    assert_eq!(provenance, agent_model_provenance());
}

#[tokio::test]
async fn v19_agent_manifest_request_tools_must_match_exactly() {
    for mismatch in ["missing", "description", "schema"] {
        let store = created_owned_session_store().await;
        let mut spec = agent_turn_spec(
            &format!("agent-request-tools-{mismatch}"),
            &format!("turn-request-tools-{mismatch}"),
        );
        match mismatch {
            "missing" => {
                spec.request_json.as_object_mut().unwrap().remove("tools");
            }
            "description" => {
                spec.request_json["tools"][0]["description"] = json!("changed description");
            }
            "schema" => {
                spec.request_json["tools"][0]["parameters"]["properties"]["depth"] =
                    json!({"type": "string"});
            }
            _ => unreachable!(),
        }
        assert!(matches!(
            store
                .start_turn_and_enqueue_agent_for_actor(
                    &owner_authz(),
                    "session-alpha",
                    StartTurnRequest {
                        turn_id: format!("turn-request-tools-{mismatch}"),
                        user_message: "Reject a provider-visible tool mismatch".into(),
                        expected_sequence: 1,
                    },
                    &format!("request-tools-{mismatch}"),
                    spec,
                )
                .await,
            Err(StorageError::InvalidAgentTransition(_))
        ));
        assert_eq!(
            store
                .get_session_for_actor(&owner_authz(), "session-alpha")
                .await
                .unwrap()
                .session
                .sequence,
            1,
            "a request-tool mismatch must not append a user turn"
        );
    }
}

#[tokio::test]
async fn agent_manifest_system_prompt_is_exact_and_fail_closed_at_admission() {
    const PROMPT: &str = "You are the manifest-bound Zeus storage test agent.";

    let exact_store = created_owned_session_store().await;
    let exact_manifest = prompt_bound_test_agent_manifest(PROMPT);
    exact_store
        .start_turn_and_enqueue_agent_for_actor(
            &owner_authz(),
            "session-alpha",
            StartTurnRequest {
                turn_id: "turn-prompt-exact".into(),
                user_message: "Admit the exact system prompt".into(),
                expected_sequence: 1,
            },
            "prompt-exact-start",
            agent_turn_spec_with_system_prompt(
                "agent-prompt-exact",
                "turn-prompt-exact",
                exact_manifest.clone(),
                PROMPT,
            ),
        )
        .await
        .unwrap();
    assert!(matches!(
        exact_store
            .claim_next_agent_model(&exact_manifest)
            .await
            .unwrap(),
        AgentModelClaimOutcome::Claimed(_)
    ));

    let bound_manifest = prompt_bound_test_agent_manifest(PROMPT);
    let cases = [
        (
            "tampered",
            bound_manifest.clone(),
            json!([
                {"role": "system", "content": "tampered prompt"},
                {"role": "user", "content": "reject this request"}
            ]),
        ),
        (
            "missing",
            bound_manifest.clone(),
            json!([{"role": "user", "content": "reject this request"}]),
        ),
        (
            "unbound",
            test_agent_manifest(),
            json!([
                {"role": "system", "content": PROMPT},
                {"role": "user", "content": "reject this request"}
            ]),
        ),
        (
            "duplicate",
            bound_manifest.clone(),
            json!([
                {"role": "system", "content": PROMPT},
                {"role": "system", "content": PROMPT},
                {"role": "user", "content": "reject this request"}
            ]),
        ),
        (
            "not-leading",
            bound_manifest.clone(),
            json!([
                {"role": "user", "content": "reject this request"},
                {"role": "system", "content": PROMPT}
            ]),
        ),
        ("empty", bound_manifest.clone(), json!([])),
        (
            "malformed",
            bound_manifest.clone(),
            json!(["not a message"]),
        ),
        (
            "system-tool-metadata",
            bound_manifest.clone(),
            json!([
                {"role": "system", "content": PROMPT, "tool_call_id": null},
                {"role": "user", "content": "reject this request"}
            ]),
        ),
        (
            "system-only",
            bound_manifest,
            json!([{"role": "system", "content": PROMPT}]),
        ),
    ];
    for (case, manifest, messages) in cases {
        let store = created_owned_session_store().await;
        let turn_id = format!("turn-prompt-{case}");
        let mut spec =
            agent_turn_spec_with_manifest(&format!("agent-prompt-{case}"), &turn_id, manifest);
        spec.request_json["messages"] = messages;
        assert!(matches!(
            store
                .start_turn_and_enqueue_agent_for_actor(
                    &owner_authz(),
                    "session-alpha",
                    StartTurnRequest {
                        turn_id,
                        user_message: "Reject a malformed prompt surface".into(),
                        expected_sequence: 1,
                    },
                    &format!("prompt-{case}-start"),
                    spec,
                )
                .await,
            Err(StorageError::InvalidAgentTransition(_))
        ));
        assert_eq!(
            store
                .get_session_for_actor(&owner_authz(), "session-alpha")
                .await
                .unwrap()
                .session
                .sequence,
            1,
            "a {case} prompt request must not append a user turn"
        );
    }

    let mut too_many_messages = vec![json!({"role": "system", "content": PROMPT})];
    for index in 0..57 {
        too_many_messages.push(json!({
            "role": if index % 2 == 0 { "user" } else { "assistant" },
            "content": format!("bounded message {index}"),
        }));
    }
    let bounded_content = "x".repeat(24 * 1024);
    let mut over_budget_messages = vec![json!({"role": "system", "content": PROMPT})];
    over_budget_messages.push(json!({"role": "user", "content": bounded_content}));
    over_budget_messages.push(json!({"role": "assistant", "content": bounded_content}));
    over_budget_messages.push(json!({"role": "user", "content": bounded_content}));
    for (case, messages) in [
        ("message-count", too_many_messages),
        ("content-budget", over_budget_messages),
    ] {
        let store = created_owned_session_store().await;
        let turn_id = format!("turn-prompt-{case}");
        let manifest = prompt_bound_test_agent_manifest(PROMPT);
        let mut spec =
            agent_turn_spec_with_manifest(&format!("agent-prompt-{case}"), &turn_id, manifest);
        spec.request_json["messages"] = Value::Array(messages);
        let typed_request =
            serde_json::from_value::<llm::ReplyRequest>(spec.request_json.clone()).unwrap();
        assert!(llm::validate_agent_reply_request(&typed_request).is_ok());
        assert!(llm::validate_initial_agent_reply_request(&typed_request).is_err());
        assert!(matches!(
            store
                .start_turn_and_enqueue_agent_for_actor(
                    &owner_authz(),
                    "session-alpha",
                    StartTurnRequest {
                        turn_id,
                        user_message: "Reject a typed provider envelope overflow".into(),
                        expected_sequence: 1,
                    },
                    &format!("prompt-{case}-start"),
                    spec,
                )
                .await,
            Err(StorageError::InvalidAgentTransition(_))
        ));
        assert_eq!(
            store
                .get_session_for_actor(&owner_authz(), "session-alpha")
                .await
                .unwrap()
                .session
                .sequence,
            1,
            "a typed {case} overflow must fail before admission"
        );
    }
}

#[tokio::test]
async fn agent_continuation_keeps_the_manifest_bound_system_prompt() {
    const PROMPT: &str = "You are the manifest-bound continuation agent.";

    for case in ["exact", "tampered", "missing", "malformed"] {
        let store = created_owned_session_store().await;
        let manifest = prompt_bound_test_agent_manifest(PROMPT);
        let turn_id = format!("turn-prompt-continuation-{case}");
        store
            .start_turn_and_enqueue_agent_for_actor(
                &owner_authz(),
                "session-alpha",
                StartTurnRequest {
                    turn_id: turn_id.clone(),
                    user_message: "Continue with the same prompt authority".into(),
                    expected_sequence: 1,
                },
                &format!("prompt-continuation-{case}-start"),
                agent_turn_spec_with_system_prompt(
                    &format!("agent-prompt-continuation-{case}"),
                    &turn_id,
                    manifest.clone(),
                    PROMPT,
                ),
            )
            .await
            .unwrap();
        let AgentModelClaimOutcome::Claimed(job) =
            store.claim_next_agent_model(&manifest).await.unwrap()
        else {
            panic!("the initial prompt-bound model job must be claimable");
        };
        let call_id = format!("agent-call-prompt-continuation-{case}");
        let call = agent_tool_call_spec(&call_id, PolicyDecision::Allow);
        store
            .complete_agent_model_success(AgentModelSuccessCommit {
                job_id: job.id,
                response_json: agent_tool_response_json(&call),
                resolution: AgentModelResolution::ToolCall { call: call.clone() },
            })
            .await
            .unwrap();
        assert!(matches!(
            store.claim_next_agent_tool(&manifest).await.unwrap(),
            AgentToolClaimOutcome::Claimed(_)
        ));
        let mut messages = vec![
            json!({
                "role": "user",
                "content": "Continue with the same prompt authority",
            }),
            json!({
                "role": "assistant",
                "content": "",
                "tool_call": {
                    "id": call.provider_call_id,
                    "name": call.tool_name,
                    "arguments": call.arguments_json,
                },
            }),
            json!({
                "role": "tool",
                "content": "known prompt-bound result",
                "tool_call_id": call.provider_call_id,
            }),
        ];
        match case {
            "exact" => messages.insert(
                0,
                json!({
                    "role": "system",
                    "content": PROMPT,
                }),
            ),
            "tampered" => messages.insert(
                0,
                json!({
                    "role": "system",
                    "content": "tampered continuation prompt",
                }),
            ),
            "missing" => {}
            "malformed" => {
                messages.remove(1);
                messages.insert(
                    0,
                    json!({
                        "role": "system",
                        "content": PROMPT,
                    }),
                );
            }
            _ => unreachable!(),
        }
        let next_request = agent_request_with_tools(json!({"messages": messages}), &manifest);
        if case == "exact" {
            let typed_request =
                serde_json::from_value::<llm::ReplyRequest>(next_request.clone()).unwrap();
            assert!(llm::validate_agent_reply_request(&typed_request).is_ok());
            assert!(llm::validate_initial_agent_reply_request(&typed_request).is_err());
        }
        let completion = store
            .complete_agent_tool(AgentToolCompletionCommit {
                call_id,
                status: AgentToolCallStatus::Succeeded,
                result_json: json!({"ok": true}),
                provider_request_id: Some(format!("connector-prompt-{case}")),
                next_request_json: Some(next_request),
            })
            .await;
        if case == "exact" {
            assert!(matches!(
                completion.unwrap(),
                AgentToolCompletion::ModelQueued { .. }
            ));
            let AgentModelClaimOutcome::Claimed(continuation) =
                store.claim_next_agent_model(&manifest).await.unwrap()
            else {
                panic!("the exact prompt-bound continuation must be claimable");
            };
            assert_eq!(continuation.request_json["messages"][0]["content"], PROMPT);
        } else {
            assert!(matches!(
                completion,
                Err(StorageError::InvalidAgentTransition(_))
            ));
        }
    }
}

#[tokio::test]
async fn agent_model_claim_rejects_an_initial_envelope_violation_before_release() {
    const PROMPT: &str = "You are the immutable model-claim prompt.";
    let database = TestDatabase::new();
    let store = created_owned_file_session_store(database.path()).await;
    let manifest = prompt_bound_test_agent_manifest(PROMPT);
    store
        .start_turn_and_enqueue_agent_for_actor(
            &owner_authz(),
            "session-alpha",
            StartTurnRequest {
                turn_id: "turn-prompt-claim-tamper".into(),
                user_message: "Detect prompt tampering before release".into(),
                expected_sequence: 1,
            },
            "prompt-claim-tamper-start",
            agent_turn_spec_with_system_prompt(
                "agent-prompt-claim-tamper",
                "turn-prompt-claim-tamper",
                manifest.clone(),
                PROMPT,
            ),
        )
        .await
        .unwrap();
    let mut messages = vec![json!({"role": "system", "content": PROMPT})];
    for index in 0..57 {
        messages.push(json!({
            "role": if index % 2 == 0 { "user" } else { "assistant" },
            "content": format!("generic-valid initial claim message {index}"),
        }));
    }
    let invalid_initial_request =
        agent_request_with_tools(json!({"messages": messages}), &manifest);
    let typed_request =
        serde_json::from_value::<llm::ReplyRequest>(invalid_initial_request.clone()).unwrap();
    assert!(llm::validate_agent_reply_request(&typed_request).is_ok());
    assert!(llm::validate_initial_agent_reply_request(&typed_request).is_err());
    replace_queued_agent_model_request(
        database.path(),
        "agent-prompt-claim-tamper",
        1,
        &invalid_initial_request,
    );

    let AgentModelClaimOutcome::Rejected(completion) =
        store.claim_next_agent_model(&manifest).await.unwrap()
    else {
        panic!("an initial-only envelope violation must be rejected before provider release");
    };
    assert_eq!(completion.agent.status, AgentTurnStatus::Failed);
    let connection = rusqlite::Connection::open(database.path()).unwrap();
    assert_eq!(
        connection
            .query_row("SELECT COUNT(*) FROM agent_run_epochs", [], |row| {
                row.get::<_, i64>(0)
            })
            .unwrap(),
        0,
        "an initial-only envelope violation must not create a RunEpoch"
    );
}

#[tokio::test]
async fn prompt_identity_revision_cannot_rebind_to_different_content() {
    const FIRST_PROMPT: &str = "You are the first immutable prompt revision.";
    const CONFLICTING_PROMPT: &str = "You are conflicting content under the same revision.";
    let database = TestDatabase::new();
    let store = created_owned_file_session_store(database.path()).await;
    let first_manifest = prompt_bound_test_agent_manifest(FIRST_PROMPT);
    store
        .start_turn_and_enqueue_agent_for_actor(
            &owner_authz(),
            "session-alpha",
            StartTurnRequest {
                turn_id: "turn-prompt-identity-first".into(),
                user_message: "Persist the first prompt identity".into(),
                expected_sequence: 1,
            },
            "prompt-identity-first-start",
            agent_turn_spec_with_system_prompt(
                "agent-prompt-identity-first",
                "turn-prompt-identity-first",
                first_manifest.clone(),
                FIRST_PROMPT,
            ),
        )
        .await
        .unwrap();
    let AgentModelClaimOutcome::Claimed(job) =
        store.claim_next_agent_model(&first_manifest).await.unwrap()
    else {
        panic!("the first prompt identity must be claimable");
    };
    let AgentModelCompletion::Final(first_completion) = store
        .complete_agent_model_success(AgentModelSuccessCommit {
            job_id: job.id,
            response_json: agent_final_response_json("first prompt completed"),
            resolution: AgentModelResolution::Final {
                assistant_message: "first prompt completed".into(),
                provenance: agent_model_provenance(),
            },
        })
        .await
        .unwrap()
    else {
        panic!("the first prompt-bound turn must finish");
    };

    let conflicting_manifest = prompt_bound_test_agent_manifest(CONFLICTING_PROMPT);
    let before_sequence = first_completion.session.sequence;
    let error = store
        .start_turn_and_enqueue_agent_for_actor(
            &owner_authz(),
            "session-alpha",
            StartTurnRequest {
                turn_id: "turn-prompt-identity-conflict".into(),
                user_message: "Reject prompt identity rebinding".into(),
                expected_sequence: before_sequence,
            },
            "prompt-identity-conflict-start",
            agent_turn_spec_with_system_prompt(
                "agent-prompt-identity-conflict",
                "turn-prompt-identity-conflict",
                conflicting_manifest.clone(),
                CONFLICTING_PROMPT,
            ),
        )
        .await
        .unwrap_err();
    assert!(
        matches!(error, StorageError::InvalidAgentTransition(message)
            if message.contains("already bound to different content"))
    );
    assert_eq!(
        store
            .get_session_for_actor(&owner_authz(), "session-alpha")
            .await
            .unwrap()
            .session
            .sequence,
        before_sequence,
        "prompt identity conflict must roll back the entire turn admission"
    );
    let connection = rusqlite::Connection::open(database.path()).unwrap();
    assert_eq!(
        connection
            .query_row(
                "SELECT COUNT(*) FROM agent_deployment_manifests",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        1
    );
    drop(connection);
    drop(store);

    let connection = rusqlite::Connection::open(database.path()).unwrap();
    connection
        .execute(
            r#"INSERT INTO agent_deployment_manifests(
                   digest, schema_version, envelope_json, created_at
               ) VALUES (?1, ?2, ?3, '2026-08-27T00:00:00.000Z')"#,
            params![
                conflicting_manifest.digest,
                i64::from(conflicting_manifest.schema_version),
                String::from_utf8(conflicting_manifest.canonical_json_bytes().unwrap()).unwrap(),
            ],
        )
        .unwrap();
    drop(connection);
    let error = match SqliteStore::open(database.path()).await {
        Ok(_) => panic!("conflicting durable prompt identities must fail startup integrity"),
        Err(error) => error,
    };
    assert!(matches!(error, StorageError::CorruptData(message)
            if message.contains("conflicting durable content bindings")));
}

#[tokio::test]
async fn agent_model_claim_rejects_provider_tool_policy_and_profile_manifest_drift() {
    let cases = [
        (
            "provider",
            mutate_test_agent_manifest(|spec| spec.provider.provider_id = "other-provider".into()),
        ),
        (
            "tool",
            mutate_test_agent_manifest(|spec| spec.tools[0].version = "2.0.0".into()),
        ),
        (
            "policy",
            mutate_test_agent_manifest(|spec| spec.policy.revision = "local/v2".into()),
        ),
        (
            "profile",
            mutate_test_agent_manifest(|spec| spec.profile = "production-guarded".into()),
        ),
    ];
    for (case, current_manifest) in cases {
        let store = created_owned_session_store().await;
        store
            .start_turn_and_enqueue_agent_for_actor(
                &owner_authz(),
                "session-alpha",
                StartTurnRequest {
                    turn_id: format!("turn-manifest-drift-{case}"),
                    user_message: format!("Reject {case} deployment drift"),
                    expected_sequence: 1,
                },
                &format!("manifest-drift-{case}"),
                agent_turn_spec(
                    &format!("agent-manifest-drift-{case}"),
                    &format!("turn-manifest-drift-{case}"),
                ),
            )
            .await
            .unwrap();
        let AgentModelClaimOutcome::Rejected(completion) = store
            .claim_next_agent_model(&current_manifest)
            .await
            .unwrap()
        else {
            panic!("{case} manifest drift must reject before provider execution");
        };
        assert_eq!(completion.agent.status, AgentTurnStatus::Failed);
        assert_eq!(
            completion
                .agent
                .last_error_json
                .as_ref()
                .and_then(|error| error.get("code"))
                .and_then(Value::as_str),
            Some("deployment_unavailable")
        );
        assert!(matches!(
            store
                .claim_next_agent_model(&test_agent_manifest())
                .await
                .unwrap(),
            AgentModelClaimOutcome::NotAvailable
        ));
    }
}

#[tokio::test]
async fn agent_tool_claim_rejects_manifest_drift_before_dispatch() {
    let database = TestDatabase::new();
    let store = created_owned_file_session_store(database.path()).await;
    let manifest = test_agent_manifest();
    store
        .start_turn_and_enqueue_agent_for_actor(
            &owner_authz(),
            "session-alpha",
            StartTurnRequest {
                turn_id: "turn-tool-manifest-drift".into(),
                user_message: "Do not dispatch after tool deployment drift".into(),
                expected_sequence: 1,
            },
            "tool-manifest-drift-start",
            agent_turn_spec_with_manifest(
                "agent-tool-manifest-drift",
                "turn-tool-manifest-drift",
                manifest.clone(),
            ),
        )
        .await
        .unwrap();
    let AgentModelClaimOutcome::Claimed(job) =
        store.claim_next_agent_model(&manifest).await.unwrap()
    else {
        panic!("the unchanged model deployment must be claimable");
    };
    let call = agent_tool_call_spec("agent-call-tool-manifest-drift", PolicyDecision::Allow);
    store
        .complete_agent_model_success(AgentModelSuccessCommit {
            job_id: job.id,
            response_json: agent_tool_response_json(&call),
            resolution: AgentModelResolution::ToolCall { call: call.clone() },
        })
        .await
        .unwrap();
    let drifted = mutate_test_agent_manifest(|spec| {
        spec.tools[0].description = "A changed provider-visible description.".into();
    });
    let AgentToolClaimOutcome::Rejected(completion) =
        store.claim_next_agent_tool(&drifted).await.unwrap()
    else {
        panic!("tool manifest drift must reject before connector execution");
    };
    assert_eq!(completion.agent.status, AgentTurnStatus::Failed);
    assert_eq!(
        completion
            .agent
            .last_error_json
            .as_ref()
            .and_then(|error| error.get("code"))
            .and_then(Value::as_str),
        Some("deployment_unavailable")
    );
    let detail = store
        .agent_turn_detail_for_actor(&owner_authz(), "session-alpha", "turn-tool-manifest-drift")
        .await
        .unwrap();
    assert_eq!(detail.calls[0].status, AgentToolCallStatus::NotDispatched);
    assert_eq!(
        detail.calls[0]
            .error
            .as_ref()
            .and_then(|error| error.get("code"))
            .and_then(Value::as_str),
        Some("deployment_unavailable")
    );
    let connection = rusqlite::Connection::open(database.path()).unwrap();
    let (status, result_json, completion_request, started_at): (
        String,
        String,
        Option<String>,
        Option<String>,
    ) = connection
        .query_row(
            r#"SELECT status, result_json, completion_next_request_json, started_at
               FROM agent_tool_calls WHERE call_id = ?1"#,
            [&call.call_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .unwrap();
    assert_eq!(status, "not_dispatched");
    assert_eq!(completion_request, None);
    assert_eq!(
        started_at, None,
        "a rejected claim never crossed the tool release checkpoint"
    );
    let epoch_count: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM agent_run_epochs WHERE tool_call_id = ?1",
            [&call.call_id],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        epoch_count, 0,
        "a rejected claim must not create a RunEpoch"
    );
    assert_eq!(
        serde_json::from_str::<Value>(&result_json).unwrap()["code"],
        "deployment_unavailable"
    );
}

#[tokio::test]
async fn v18_agents_migrate_unbound_terminal_readable_and_queued_fail_closed() {
    let manifest = test_agent_manifest();

    let terminal_database = TestDatabase::new();
    let terminal_store = created_owned_file_session_store(terminal_database.path()).await;
    terminal_store
        .start_turn_and_enqueue_agent_for_actor(
            &owner_authz(),
            "session-alpha",
            StartTurnRequest {
                turn_id: "turn-v18-manifest-terminal".into(),
                user_message: "Preserve legacy terminal history".into(),
                expected_sequence: 1,
            },
            "v18-manifest-terminal-start",
            agent_turn_spec_with_manifest(
                "agent-v18-manifest-terminal",
                "turn-v18-manifest-terminal",
                manifest.clone(),
            ),
        )
        .await
        .unwrap();
    let AgentModelClaimOutcome::Claimed(job) = terminal_store
        .claim_next_agent_model(&manifest)
        .await
        .unwrap()
    else {
        panic!("the pre-downgrade model must be claimable");
    };
    terminal_store
        .complete_agent_model_success(AgentModelSuccessCommit {
            job_id: job.id,
            response_json: agent_final_response_json("legacy terminal reply"),
            resolution: AgentModelResolution::Final {
                assistant_message: "legacy terminal reply".into(),
                provenance: agent_model_provenance(),
            },
        })
        .await
        .unwrap();
    drop(terminal_store);
    let connection = rusqlite::Connection::open(terminal_database.path()).unwrap();
    downgrade_agent_deployment_manifest_fixture_to_v18(&connection);
    assert_eq!(
        connection
            .query_row("SELECT MAX(version) FROM schema_migrations", [], |row| {
                row.get::<_, i64>(0)
            })
            .unwrap(),
        18
    );
    drop(connection);
    let migrated_terminal = SqliteStore::open(terminal_database.path()).await.unwrap();
    assert_eq!(
        migrated_terminal
            .agent_deployment_manifest_for_actor(
                &owner_authz(),
                "session-alpha",
                "turn-v18-manifest-terminal",
            )
            .await
            .unwrap(),
        None
    );
    let detail = migrated_terminal
        .agent_turn_detail_for_actor(
            &owner_authz(),
            "session-alpha",
            "turn-v18-manifest-terminal",
        )
        .await
        .unwrap();
    assert_eq!(detail.status, AgentTurnStatus::Succeeded);
    assert_eq!(detail.deployment_manifest_digest, None);
    migrated_terminal.verify_integrity().await.unwrap();

    let queued_database = TestDatabase::new();
    let queued_store = created_owned_file_session_store(queued_database.path()).await;
    queued_store
        .start_turn_and_enqueue_agent_for_actor(
            &owner_authz(),
            "session-alpha",
            StartTurnRequest {
                turn_id: "turn-v18-manifest-queued".into(),
                user_message: "Fail a legacy queued model closed".into(),
                expected_sequence: 1,
            },
            "v18-manifest-queued-start",
            agent_turn_spec_with_manifest(
                "agent-v18-manifest-queued",
                "turn-v18-manifest-queued",
                manifest.clone(),
            ),
        )
        .await
        .unwrap();
    drop(queued_store);
    let connection = rusqlite::Connection::open(queued_database.path()).unwrap();
    downgrade_agent_deployment_manifest_fixture_to_v18(&connection);
    drop(connection);
    let migrated_queued = SqliteStore::open(queued_database.path()).await.unwrap();
    let AgentModelClaimOutcome::Rejected(completion) = migrated_queued
        .claim_next_agent_model(&manifest)
        .await
        .unwrap()
    else {
        panic!("an unbound v18 queued model must fail closed at its first claim");
    };
    assert_eq!(completion.agent.status, AgentTurnStatus::Failed);
    assert_eq!(completion.agent.deployment_manifest_digest, None);
    assert_eq!(
        completion
            .agent
            .last_error_json
            .as_ref()
            .and_then(|error| error.get("code"))
            .and_then(Value::as_str),
        Some("deployment_unavailable")
    );
    let connection = rusqlite::Connection::open(queued_database.path()).unwrap();
    let (status, error_json): (String, String) = connection
        .query_row(
            "SELECT status, error_json FROM agent_model_jobs WHERE agent_id = ?1",
            ["agent-v18-manifest-queued"],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(status, "failed");
    assert_eq!(
        serde_json::from_str::<Value>(&error_json).unwrap()["code"],
        "deployment_unavailable"
    );
}

#[tokio::test]
async fn v19_promptless_system_and_dotted_tool_terminal_history_reopens_readable() {
    let database = TestDatabase::new();
    let current_manifest = test_agent_manifest();
    let store = created_owned_file_session_store(database.path()).await;
    store
        .start_turn_and_enqueue_agent_for_actor(
            &owner_authz(),
            "session-alpha",
            StartTurnRequest {
                turn_id: "turn-v19-dotted-terminal".into(),
                user_message: "Preserve a historical dotted provider tool".into(),
                expected_sequence: 1,
            },
            "v19-dotted-terminal-start",
            agent_turn_spec_with_manifest(
                "agent-v19-dotted-terminal",
                "turn-v19-dotted-terminal",
                current_manifest.clone(),
            ),
        )
        .await
        .unwrap();
    let AgentModelClaimOutcome::Claimed(job) = store
        .claim_next_agent_model(&current_manifest)
        .await
        .unwrap()
    else {
        panic!("the pre-v19-fixture model must be claimable");
    };
    store
        .complete_agent_model_success(AgentModelSuccessCommit {
            job_id: job.id,
            response_json: agent_final_response_json("legacy dotted terminal reply"),
            resolution: AgentModelResolution::Final {
                assistant_message: "legacy dotted terminal reply".into(),
                provenance: agent_model_provenance(),
            },
        })
        .await
        .unwrap();
    drop(store);

    let connection = rusqlite::Connection::open(database.path()).unwrap();
    let dotted_manifest = rewrite_agent_as_v19_promptless_legacy(
        &connection,
        "agent-v19-dotted-terminal",
        "Legacy provider prompt without a manifest binding",
    );
    drop(connection);

    let reopened = SqliteStore::open(database.path()).await.unwrap();
    assert_eq!(
        reopened
            .agent_deployment_manifest_for_actor(
                &owner_authz(),
                "session-alpha",
                "turn-v19-dotted-terminal",
            )
            .await
            .unwrap(),
        Some(dotted_manifest)
    );
    let detail = reopened
        .agent_turn_detail_for_actor(&owner_authz(), "session-alpha", "turn-v19-dotted-terminal")
        .await
        .unwrap();
    assert_eq!(detail.status, AgentTurnStatus::Succeeded);
    reopened.verify_integrity().await.unwrap();
}

#[tokio::test]
async fn v19_promptless_queued_request_fails_claim_before_run_epoch() {
    let database = TestDatabase::new();
    let current_manifest = test_agent_manifest();
    let store = created_owned_file_session_store(database.path()).await;
    store
        .start_turn_and_enqueue_agent_for_actor(
            &owner_authz(),
            "session-alpha",
            StartTurnRequest {
                turn_id: "turn-v19-dotted-queued".into(),
                user_message: "Reject a queued historical provider request".into(),
                expected_sequence: 1,
            },
            "v19-dotted-queued-start",
            agent_turn_spec_with_manifest(
                "agent-v19-dotted-queued",
                "turn-v19-dotted-queued",
                current_manifest,
            ),
        )
        .await
        .unwrap();
    drop(store);

    let connection = rusqlite::Connection::open(database.path()).unwrap();
    let dotted_manifest = rewrite_agent_as_v19_promptless_legacy(
        &connection,
        "agent-v19-dotted-queued",
        "Legacy queued provider prompt without a manifest binding",
    );
    drop(connection);

    let reopened = SqliteStore::open(database.path()).await.unwrap();
    let AgentModelClaimOutcome::Rejected(completion) = reopened
        .claim_next_agent_model(&dotted_manifest)
        .await
        .unwrap()
    else {
        panic!("a legacy provider request must fail closed at its current claim boundary");
    };
    assert_eq!(completion.agent.status, AgentTurnStatus::Failed);
    assert_eq!(
        completion
            .agent
            .last_error_json
            .as_ref()
            .and_then(|error| error.get("code"))
            .and_then(Value::as_str),
        Some("deployment_unavailable")
    );
    reopened.verify_integrity().await.unwrap();

    let connection = rusqlite::Connection::open(database.path()).unwrap();
    let (status, run_epochs): (String, i64) = connection
        .query_row(
            r#"SELECT job.status,
                      (SELECT COUNT(*) FROM agent_run_epochs epoch
                       WHERE epoch.agent_id = job.agent_id)
               FROM agent_model_jobs job
               WHERE job.agent_id = ?1 AND job.step = 1"#,
            ["agent-v19-dotted-queued"],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(status, "failed");
    assert_eq!(
        run_epochs, 0,
        "a rejected legacy claim must not create a RunEpoch"
    );
}

#[tokio::test]
async fn v18_waiting_approval_review_paths_fail_closed_without_manifest() {
    let (rejected_database, manifest, rejected_call) =
        v18_waiting_approval_manifest_fixture("reject").await;
    let rejected_store = SqliteStore::open(rejected_database.path()).await.unwrap();
    let rejected = rejected_store
        .review_agent_tool_for_actor(
            &owner_authz(),
            "session-alpha",
            "turn-v18-manifest-approval-reject",
            AgentReviewCommit {
                call_id: rejected_call.call_id.clone(),
                decision: ReviewDecision::Reject,
                note: Some("legacy deployment cannot be resumed".into()),
                idempotency_key: "v18-manifest-approval-reject".into(),
                next_request_json: Some(test_agent_request(json!({
                    "messages": [{
                        "role": "tool",
                        "content": "the legacy call was rejected",
                        "tool_call_id": rejected_call.provider_call_id,
                    }],
                }))),
            },
        )
        .await
        .unwrap();
    assert_eq!(rejected.response.agent.status, AgentTurnStatus::Failed);
    assert_eq!(
        rejected
            .response
            .agent
            .last_error
            .as_ref()
            .and_then(|error| error.get("code"))
            .and_then(Value::as_str),
        Some("deployment_unavailable")
    );
    assert_eq!(rejected.response.call.status, AgentToolCallStatus::Rejected);
    assert!(rejected.queued_model_job.is_none());
    assert!(rejected.terminal_completion.is_some());
    rejected_store.verify_integrity().await.unwrap();
    drop(rejected_store);
    let reopened_rejected = SqliteStore::open(rejected_database.path()).await.unwrap();
    reopened_rejected.verify_integrity().await.unwrap();
    drop(reopened_rejected);

    let (approved_database, _, approved_call) =
        v18_waiting_approval_manifest_fixture("approve").await;
    let approved_store = SqliteStore::open(approved_database.path()).await.unwrap();
    let approved = approved_store
        .review_agent_tool_for_actor(
            &owner_authz(),
            "session-alpha",
            "turn-v18-manifest-approval-approve",
            AgentReviewCommit {
                call_id: approved_call.call_id.clone(),
                decision: ReviewDecision::Approve,
                note: Some("approve the historical review before dispatch".into()),
                idempotency_key: "v18-manifest-approval-approve".into(),
                next_request_json: None,
            },
        )
        .await
        .unwrap();
    assert_eq!(approved.response.agent.status, AgentTurnStatus::ToolQueued);
    assert_eq!(approved.response.call.status, AgentToolCallStatus::Queued);

    let AgentToolClaimOutcome::Rejected(completion) = approved_store
        .claim_next_agent_tool(&manifest)
        .await
        .unwrap()
    else {
        panic!("an approved unbound v18 tool must fail closed before dispatch");
    };
    assert_eq!(completion.agent.status, AgentTurnStatus::Failed);
    assert_eq!(completion.agent.deployment_manifest_digest, None);
    assert_eq!(
        completion
            .agent
            .last_error_json
            .as_ref()
            .and_then(|error| error.get("code"))
            .and_then(Value::as_str),
        Some("deployment_unavailable")
    );
    let detail = approved_store
        .agent_turn_detail_for_actor(
            &owner_authz(),
            "session-alpha",
            "turn-v18-manifest-approval-approve",
        )
        .await
        .unwrap();
    assert_eq!(detail.calls[0].status, AgentToolCallStatus::NotDispatched);
    assert_eq!(
        detail.calls[0]
            .error
            .as_ref()
            .and_then(|error| error.get("code"))
            .and_then(Value::as_str),
        Some("deployment_unavailable")
    );
}

#[tokio::test]
async fn agent_manifest_collision_and_tamper_fail_closed() {
    let manifest = test_agent_manifest();

    let collision_database = TestDatabase::new();
    let collision_store = created_owned_file_session_store(collision_database.path()).await;
    let mut collision_value = serde_json::to_value(&manifest).unwrap();
    collision_value["manifest"]["deployment"]["spec"]["provider"]["provider_id"] =
        json!("collision-provider");
    let connection = rusqlite::Connection::open(collision_database.path()).unwrap();
    connection
        .execute(
            r#"INSERT INTO agent_deployment_manifests(
                   digest, schema_version, envelope_json, created_at
               ) VALUES (?1, ?2, ?3, ?4)"#,
            params![
                manifest.digest,
                i64::from(manifest.schema_version),
                serde_json::to_string(&collision_value).unwrap(),
                "2026-08-27T00:00:00.000Z",
            ],
        )
        .unwrap();
    drop(connection);
    assert!(matches!(
        collision_store
            .start_turn_and_enqueue_agent_for_actor(
                &owner_authz(),
                "session-alpha",
                StartTurnRequest {
                    turn_id: "turn-manifest-collision".into(),
                    user_message: "Do not trust a digest collision".into(),
                    expected_sequence: 1,
                },
                "manifest-collision-start",
                agent_turn_spec_with_manifest(
                    "agent-manifest-collision",
                    "turn-manifest-collision",
                    manifest.clone(),
                ),
            )
            .await,
        Err(StorageError::CorruptData(message)) if message.contains("collides")
    ));
    assert_eq!(
        collision_store
            .get_session_for_actor(&owner_authz(), "session-alpha")
            .await
            .unwrap()
            .session
            .sequence,
        1
    );

    let tamper_database = TestDatabase::new();
    let tamper_store = created_owned_file_session_store(tamper_database.path()).await;
    tamper_store
        .start_turn_and_enqueue_agent_for_actor(
            &owner_authz(),
            "session-alpha",
            StartTurnRequest {
                turn_id: "turn-manifest-tamper".into(),
                user_message: "Detect durable manifest tampering".into(),
                expected_sequence: 1,
            },
            "manifest-tamper-start",
            agent_turn_spec_with_manifest(
                "agent-manifest-tamper",
                "turn-manifest-tamper",
                manifest.clone(),
            ),
        )
        .await
        .unwrap();
    tamper_store.verify_integrity().await.unwrap();
    let connection = rusqlite::Connection::open(tamper_database.path()).unwrap();
    let update_trigger: String = connection
        .query_row(
            r#"SELECT sql FROM sqlite_schema
               WHERE type = 'trigger'
                 AND name = 'agent_deployment_manifests_reject_update'"#,
            [],
            |row| row.get(0),
        )
        .unwrap();
    let stored_json: String = connection
        .query_row(
            "SELECT envelope_json FROM agent_deployment_manifests WHERE digest = ?1",
            [&manifest.digest],
            |row| row.get(0),
        )
        .unwrap();
    let mut tampered: Value = serde_json::from_str(&stored_json).unwrap();
    tampered["manifest"]["deployment"]["spec"]["provider"]["provider_id"] =
        json!("tampered-provider");
    connection
        .execute_batch("DROP TRIGGER agent_deployment_manifests_reject_update")
        .unwrap();
    connection
        .execute(
            "UPDATE agent_deployment_manifests SET envelope_json = ?1 WHERE digest = ?2",
            params![serde_json::to_string(&tampered).unwrap(), manifest.digest],
        )
        .unwrap();
    connection.execute_batch(&update_trigger).unwrap();
    drop(connection);
    assert!(matches!(
        tamper_store.verify_integrity().await,
        Err(StorageError::CorruptData(_))
    ));
    drop(tamper_store);
    assert!(matches!(
        SqliteStore::open(tamper_database.path()).await,
        Err(StorageError::CorruptData(_))
    ));
}

#[tokio::test]
async fn agent_final_reply_commits_one_terminal_session_transaction() {
    let database = TestDatabase::new();
    let store = created_owned_file_session_store(database.path()).await;
    let request = StartTurnRequest {
        turn_id: "turn-agent-final".into(),
        user_message: "Finish this turn through the durable Agent Loop".into(),
        expected_sequence: 1,
    };
    let spec = agent_turn_spec("agent-final", &request.turn_id);
    let enqueued = store
        .start_turn_and_enqueue_agent_for_actor(
            &owner_authz(),
            "session-alpha",
            request,
            "agent-final-start",
            spec.clone(),
        )
        .await
        .unwrap();
    assert_eq!(enqueued.agent.status, AgentTurnStatus::WaitingModel);
    assert_eq!(enqueued.job.step, 1);

    let AgentModelClaimOutcome::Claimed(claimed) = store
        .claim_next_agent_model(&test_agent_manifest())
        .await
        .unwrap()
    else {
        panic!("the first Agent model step must be claimable");
    };
    assert_eq!(claimed.id, enqueued.job.id);
    let assistant_message = "The durable Agent Loop completed this turn.";
    let commit = AgentModelSuccessCommit {
        job_id: claimed.id,
        response_json: agent_final_response_json(assistant_message),
        resolution: AgentModelResolution::Final {
            assistant_message: assistant_message.into(),
            provenance: agent_model_provenance(),
        },
    };
    let completed = store
        .complete_agent_model_success(commit.clone())
        .await
        .unwrap();
    let AgentModelCompletion::Final(completed) = completed else {
        panic!("a final provider output must finish the Session turn");
    };
    assert!(!completed.replayed);
    assert_eq!(completed.agent.status, AgentTurnStatus::Succeeded);
    assert_eq!(completed.session.status, SessionStatus::Ready);
    assert_eq!(completed.session.sequence, 4);
    assert_eq!(completed.turn.status, SessionTurnStatus::Flushed);
    assert_eq!(
        completed.turn.assistant_message.as_deref(),
        Some(assistant_message)
    );
    assert_eq!(completed.events.len(), 2);
    assert!(matches!(
        completed.events[0].data,
        SessionEventData::AssistantMessage { .. }
    ));
    assert!(matches!(
        completed.events[1].data,
        SessionEventData::TurnFlushed { .. }
    ));

    let replay = store.complete_agent_model_success(commit).await.unwrap();
    let AgentModelCompletion::Final(replay) = replay else {
        panic!("a replay must reconstruct the durable final completion");
    };
    assert!(replay.replayed);
    assert_eq!(replay.agent, completed.agent);
    assert_eq!(replay.session, completed.session);
    assert_eq!(replay.turn, completed.turn);
    assert_eq!(replay.events, completed.events);

    store
        .start_turn_for_actor(
            &owner_authz(),
            "session-alpha",
            StartTurnRequest {
                turn_id: "turn-after-agent-final".into(),
                user_message: "Start another turn after the completed Agent".into(),
                expected_sequence: 4,
            },
            "turn-after-agent-final-start",
        )
        .await
        .unwrap();
    let replay_after_session_advanced = store
        .complete_agent_model_success(AgentModelSuccessCommit {
            job_id: enqueued.job.id.clone(),
            response_json: agent_final_response_json(assistant_message),
            resolution: AgentModelResolution::Final {
                assistant_message: assistant_message.into(),
                provenance: agent_model_provenance(),
            },
        })
        .await
        .unwrap();
    let AgentModelCompletion::Final(replay_after_session_advanced) = replay_after_session_advanced
    else {
        panic!("a final replay must not depend on the mutable Session head");
    };
    assert!(replay_after_session_advanced.replayed);
    assert_eq!(
        replay_after_session_advanced.session.status,
        SessionStatus::Running
    );
    assert_eq!(replay_after_session_advanced.turn.id, "turn-agent-final");
    assert!(matches!(
        store
            .claim_next_agent_model(&test_agent_manifest())
            .await
            .unwrap(),
        AgentModelClaimOutcome::NotAvailable
    ));
    assert_eq!(
        store
            .get_session_for_actor(&owner_authz(), "session-alpha")
            .await
            .unwrap()
            .events
            .len(),
        5
    );

    let flushed = store
        .flush_turn_for_actor(
            &owner_authz(),
            "session-alpha",
            FlushSessionRequest {
                turn_id: "turn-after-agent-final".into(),
                assistant_message: Some("The later turn is complete.".into()),
                expected_sequence: 5,
            },
            "turn-after-agent-final-flush",
        )
        .await
        .unwrap();
    let mut sequence = flushed.session.sequence;
    for ordinal in 0..64 {
        let turn_id = format!("turn-after-agent-final-{ordinal}");
        let started = store
            .start_turn_for_actor(
                &owner_authz(),
                "session-alpha",
                StartTurnRequest {
                    turn_id: turn_id.clone(),
                    user_message: format!("later user message {ordinal}"),
                    expected_sequence: sequence,
                },
                &format!("turn-after-agent-final-{ordinal}-start"),
            )
            .await
            .unwrap();
        let flushed = store
            .flush_turn_for_actor(
                &owner_authz(),
                "session-alpha",
                FlushSessionRequest {
                    turn_id,
                    assistant_message: Some(format!("later assistant message {ordinal}")),
                    expected_sequence: started.session.sequence,
                },
                &format!("turn-after-agent-final-{ordinal}-flush"),
            )
            .await
            .unwrap();
        sequence = flushed.session.sequence;
    }

    let replay_after_large_history = store
        .complete_agent_model_success(AgentModelSuccessCommit {
            job_id: enqueued.job.id,
            response_json: agent_final_response_json(assistant_message),
            resolution: AgentModelResolution::Final {
                assistant_message: assistant_message.into(),
                provenance: agent_model_provenance(),
            },
        })
        .await
        .unwrap();
    let AgentModelCompletion::Final(replay_after_large_history) = replay_after_large_history else {
        panic!("a final replay must remain bounded after extensive later history");
    };
    assert!(replay_after_large_history.replayed);
    assert_eq!(replay_after_large_history.turn.id, "turn-agent-final");
    assert_eq!(replay_after_large_history.events, completed.events);

    let connection = rusqlite::Connection::open(database.path()).unwrap();
    let final_plan = explain_query_plan(
        &connection,
        r#"SELECT sequence, event_id, event_kind, payload_version, payload_json,
                  turn_id, created_at
           FROM session_events INDEXED BY session_events_turn_kind_idx
           WHERE session_id = ?1 AND turn_id = ?2 AND turn_id IS NOT NULL
             AND event_kind = ?3
           ORDER BY sequence LIMIT ?4"#,
        params![
            "session-alpha",
            "turn-agent-final",
            "assistant_message",
            2_i64
        ],
    );
    assert!(
        final_plan.contains("session_events_turn_kind_idx"),
        "Agent final replay must use its bounded turn/kind index: {final_plan}"
    );
    let terminal_plan = explain_query_plan(
        &connection,
        r#"SELECT sequence, event_id, event_kind, payload_version, payload_json,
                  turn_id, created_at
           FROM session_events INDEXED BY session_events_turn_kind_idx
           WHERE session_id = ?1 AND turn_id = ?2 AND turn_id IS NOT NULL
             AND event_kind = ?3
           ORDER BY sequence LIMIT ?4"#,
        params![
            "session-alpha",
            "turn-agent-final",
            "turn_interrupted",
            2_i64
        ],
    );
    assert!(
        terminal_plan.contains("session_events_turn_kind_idx"),
        "Agent terminal replay must use its bounded turn/kind index: {terminal_plan}"
    );
}

#[tokio::test]
async fn agent_tool_result_and_continuation_are_atomic_and_idempotent() {
    let store = created_owned_session_store().await;
    let request = StartTurnRequest {
        turn_id: "turn-agent-tool".into(),
        user_message: "Inspect the workspace before answering".into(),
        expected_sequence: 1,
    };
    let enqueued = store
        .start_turn_and_enqueue_agent_for_actor(
            &owner_authz(),
            "session-alpha",
            request,
            "agent-tool-start",
            agent_turn_spec("agent-tool", "turn-agent-tool"),
        )
        .await
        .unwrap();
    let AgentModelClaimOutcome::Claimed(claimed) = store
        .claim_next_agent_model(&test_agent_manifest())
        .await
        .unwrap()
    else {
        panic!("the first Agent model step must be claimable");
    };
    assert_eq!(claimed.id, enqueued.job.id);

    let call = agent_tool_call_spec("agent-call-allow", PolicyDecision::Allow);
    let proposal_response = agent_tool_response_json(&call);
    let proposed = store
        .complete_agent_model_success(AgentModelSuccessCommit {
            job_id: claimed.id,
            response_json: proposal_response.clone(),
            resolution: AgentModelResolution::ToolCall { call: call.clone() },
        })
        .await
        .unwrap();
    let AgentModelCompletion::ToolCall {
        agent,
        call: stored_call,
    } = proposed
    else {
        panic!("an allowed tool proposal must become durable queued work");
    };
    assert_eq!(agent.status, AgentTurnStatus::ToolQueued);
    assert_eq!(stored_call.status, AgentToolCallStatus::Queued);

    let AgentToolClaimOutcome::Claimed(work) = store
        .claim_next_agent_tool(&test_agent_manifest())
        .await
        .unwrap()
    else {
        panic!("the admitted Agent tool must be claimable");
    };
    assert_eq!(work.call.call_id, call.call_id);
    assert_eq!(work.call.status, AgentToolCallStatus::Running);
    assert_eq!(work.model_job.step, 1);

    let result_json = json!({"entries": ["Cargo.toml", "apps", "crates"]});
    let next_request_json = test_agent_request(json!({
        "messages": [
            {"role": "user", "content": "Inspect the workspace before answering"},
            {
                "role": "assistant",
                "content": "",
                "tool_call": {
                    "id": call.provider_call_id,
                    "name": call.tool_name,
                    "arguments": call.arguments_json,
                }
            },
            {
                "role": "tool",
                "content": serde_json::to_string(&result_json).unwrap(),
                "tool_call_id": "provider-call-agent-call-allow"
            }
        ]
    }));
    let completion_commit = AgentToolCompletionCommit {
        call_id: call.call_id,
        status: AgentToolCallStatus::Succeeded,
        result_json: result_json.clone(),
        provider_request_id: Some("connector-request-1".into()),
        next_request_json: Some(next_request_json.clone()),
    };
    let completed = store
        .complete_agent_tool(completion_commit.clone())
        .await
        .unwrap();
    let AgentToolCompletion::ModelQueued { agent, job } = completed else {
        panic!("a known tool result must atomically enqueue the model continuation");
    };
    assert_eq!(agent.status, AgentTurnStatus::WaitingModel);
    assert_eq!(job.step, 2);
    assert_eq!(job.request_json, next_request_json);

    let replay = store
        .complete_agent_tool(completion_commit.clone())
        .await
        .unwrap();
    let AgentToolCompletion::ModelQueued {
        agent: replayed_agent,
        job: replayed_job,
    } = replay
    else {
        panic!("a known Agent tool completion must be replayable");
    };
    assert_eq!(replayed_agent, agent);
    assert_eq!(replayed_job, job);
    let mut conflicting_completion = completion_commit;
    conflicting_completion.next_request_json = Some(json!({
        "messages": [{
            "role": "user",
            "content": "a conflicting continuation must not replay",
        }],
    }));
    assert!(matches!(
        store.complete_agent_tool(conflicting_completion).await,
        Err(StorageError::InvalidAgentTransition(_))
    ));
    let detail = store
        .agent_turn_detail_for_actor(&owner_authz(), "session-alpha", "turn-agent-tool")
        .await
        .unwrap();
    assert_eq!(detail.calls.len(), 1);
    assert_eq!(detail.calls[0].status, AgentToolCallStatus::Succeeded);
    assert_eq!(detail.calls[0].output.as_ref(), Some(&result_json));

    let execution = store
        .agent_execution_explain_for_actor(&owner_authz(), "session-alpha", "turn-agent-tool")
        .await
        .unwrap();
    assert_eq!(execution.epochs.len(), 2);
    assert_eq!(execution.facts.len(), 5);
    assert_eq!(
        execution
            .epochs
            .iter()
            .map(|epoch| epoch.status)
            .collect::<Vec<_>>(),
        [
            execution::EpochExecutionStatus::Succeeded,
            execution::EpochExecutionStatus::Succeeded,
        ]
    );
    let model_epoch = store
        .agent_run_epoch_explain_for_actor(&owner_authz(), "session-alpha", "turn-agent-tool", 1)
        .await
        .unwrap();
    assert_eq!(model_epoch.linked_tools.len(), 1);
    assert_eq!(model_epoch.linked_tools[0].call_id, stored_call.call_id);
    let execution::EpochOutcomeMaterial::Succeeded { response, .. } = model_epoch.outcome else {
        panic!("the model tool proposal must retain its exact provider response");
    };
    assert_eq!(response.value, proposal_response);

    let AgentModelClaimOutcome::Claimed(continuation) = store
        .claim_next_agent_model(&test_agent_manifest())
        .await
        .unwrap()
    else {
        panic!("the continuation model job must remain claimable");
    };
    assert_eq!(continuation.id, job.id);
    assert_eq!(continuation.step, 2);
}

#[tokio::test]
async fn v17_agent_tool_completion_replay_backfills_from_the_continuation_job() {
    let fixture = v17_agent_tool_path_fixture(V17AgentToolPath::Completed).await;
    let migrated = SqliteStore::open(fixture.database.path()).await.unwrap();
    migrated.readiness().await.unwrap();
    let binding = agent_tool_replay_binding_row(fixture.database.path(), &fixture.call_id);
    assert!(binding.started && binding.finished && binding.has_result && binding.has_next_job);
    assert_eq!(
        binding.binding.as_ref(),
        fixture.tool_replay.next_request_json.as_ref()
    );

    let replay = migrated
        .complete_agent_tool(fixture.tool_replay.clone())
        .await
        .unwrap();
    assert!(matches!(replay, AgentToolCompletion::ModelQueued { .. }));

    let mut conflicting_commit = fixture.tool_replay;
    conflicting_commit.next_request_json = Some(json!({
        "messages": [{"role": "user", "content": "conflicting migrated request"}],
    }));
    assert!(matches!(
        migrated.complete_agent_tool(conflicting_commit).await,
        Err(StorageError::InvalidAgentTransition(message))
            if message.contains("durable continuation request")
    ));
}

#[tokio::test]
async fn v17_non_completion_tool_paths_remain_unbound_and_fail_closed() {
    for path in [
        V17AgentToolPath::PolicyDenied,
        V17AgentToolPath::ApprovalRejected,
        V17AgentToolPath::Queued,
        V17AgentToolPath::Started,
        V17AgentToolPath::LegacyTerminal,
    ] {
        let fixture = v17_agent_tool_path_fixture(path).await;
        let migrated = SqliteStore::open(fixture.database.path()).await.unwrap();
        migrated.readiness().await.unwrap();
        if matches!(path, V17AgentToolPath::Started) {
            let recovered = migrated.recover_started_agent_work().await.unwrap();
            assert_eq!(recovered.len(), 1);
        }
        let before = agent_tool_replay_binding_row(fixture.database.path(), &fixture.call_id);
        assert_eq!(before.binding, None, "{path:?} must remain unbound");
        match path {
            V17AgentToolPath::PolicyDenied => {
                assert_eq!(before.status, "not_dispatched");
                assert!(!before.started && before.finished && before.has_result);
                assert!(before.has_next_job);
                let replay = migrated
                    .complete_agent_model_success(
                        fixture
                            .model_replay
                            .clone()
                            .expect("policy denial keeps its model replay"),
                    )
                    .await
                    .unwrap();
                assert!(matches!(replay, AgentModelCompletion::ToolCall { .. }));
            }
            V17AgentToolPath::ApprovalRejected => {
                assert_eq!(before.status, "rejected");
                assert!(!before.started && before.finished && before.has_result);
                assert!(before.has_next_job);
                let replay = migrated
                    .review_agent_tool_for_actor(
                        &owner_authz(),
                        "session-alpha",
                        &fixture.turn_id,
                        fixture
                            .review_replay
                            .clone()
                            .expect("approval rejection keeps its review replay"),
                    )
                    .await
                    .unwrap();
                assert!(replay.response.replayed);
            }
            V17AgentToolPath::Queued => {
                assert_eq!(before.status, "queued");
                assert!(!before.started && !before.finished && !before.has_result);
                assert!(!before.has_next_job);
            }
            V17AgentToolPath::Started => {
                assert_eq!(before.status, "outcome_unknown");
                assert!(before.started && before.finished && before.has_result);
                assert!(!before.has_next_job);
            }
            V17AgentToolPath::LegacyTerminal => {
                assert_eq!(before.status, "succeeded");
                assert!(before.started && before.finished && before.has_result);
                assert!(!before.has_next_job);
            }
            V17AgentToolPath::Completed => unreachable!("not part of the non-completion matrix"),
        }

        assert!(matches!(
            migrated
                .complete_agent_tool(fixture.tool_replay.clone())
                .await,
            Err(StorageError::InvalidAgentTransition(_))
        ));
        let after = agent_tool_replay_binding_row(fixture.database.path(), &fixture.call_id);
        assert_eq!(after.status, before.status);
        assert_eq!(after.binding, None);
    }
}

#[tokio::test]
async fn agent_tool_completion_binding_integrity_rejects_lifecycle_shape_and_job_mismatch() {
    let lifecycle = v17_agent_tool_path_fixture(V17AgentToolPath::PolicyDenied).await;
    let lifecycle_store = SqliteStore::open(lifecycle.database.path()).await.unwrap();
    force_agent_tool_completion_binding(
        lifecycle.database.path(),
        &lifecycle.call_id,
        r#"{"messages":[{"role":"tool","content":"invalid lifecycle"}]}"#,
    );
    assert_agent_tool_completion_binding_integrity_error(
        lifecycle_store,
        lifecycle.database.path(),
    )
    .await;

    let scalar = v17_agent_tool_path_fixture(V17AgentToolPath::LegacyTerminal).await;
    let scalar_store = SqliteStore::open(scalar.database.path()).await.unwrap();
    force_agent_tool_completion_binding(scalar.database.path(), &scalar.call_id, "7");
    assert_agent_tool_completion_binding_integrity_error(scalar_store, scalar.database.path())
        .await;

    let mismatch = v17_agent_tool_path_fixture(V17AgentToolPath::Completed).await;
    let mismatch_store = SqliteStore::open(mismatch.database.path()).await.unwrap();
    force_agent_tool_completion_binding(
        mismatch.database.path(),
        &mismatch.call_id,
        r#"{"messages":[{"role":"tool","content":"wrong job request"}]}"#,
    );
    assert_agent_tool_completion_binding_integrity_error(mismatch_store, mismatch.database.path())
        .await;
}

#[tokio::test]
async fn agent_known_tool_results_preserve_scalar_and_array_values() {
    for (case, result_json) in [
        ("scalar", json!("connector-ok")),
        ("array", json!(["Cargo.toml", "crates"])),
    ] {
        let store = created_owned_session_store().await;
        let turn_id = format!("turn-agent-result-{case}");
        let agent_id = format!("agent-result-{case}");
        store
            .start_turn_and_enqueue_agent_for_actor(
                &owner_authz(),
                "session-alpha",
                StartTurnRequest {
                    turn_id: turn_id.clone(),
                    user_message: format!("Return a {case} tool result"),
                    expected_sequence: 1,
                },
                &format!("agent-result-{case}-start"),
                agent_turn_spec(&agent_id, &turn_id),
            )
            .await
            .unwrap();
        let AgentModelClaimOutcome::Claimed(model_job) = store
            .claim_next_agent_model(&test_agent_manifest())
            .await
            .unwrap()
        else {
            panic!("the initial Agent model job must be claimable");
        };
        let call =
            agent_tool_call_spec(&format!("agent-call-result-{case}"), PolicyDecision::Allow);
        store
            .complete_agent_model_success(AgentModelSuccessCommit {
                job_id: model_job.id,
                response_json: agent_tool_response_json(&call),
                resolution: AgentModelResolution::ToolCall { call: call.clone() },
            })
            .await
            .unwrap();
        let AgentToolClaimOutcome::Claimed(_) = store
            .claim_next_agent_tool(&test_agent_manifest())
            .await
            .unwrap()
        else {
            panic!("the Agent tool call must be claimable");
        };
        let next_request_json = test_agent_request(json!({
            "messages": [
                {"role": "user", "content": format!("Return a {case} tool result")},
                {
                    "role": "assistant",
                    "content": "",
                    "tool_call": {
                        "id": call.provider_call_id,
                        "name": call.tool_name,
                        "arguments": call.arguments_json,
                    }
                },
                {
                    "role": "tool",
                    "content": serde_json::to_string(&result_json).unwrap(),
                    "tool_call_id": call.provider_call_id,
                }
            ]
        }));
        let commit = AgentToolCompletionCommit {
            call_id: call.call_id,
            status: AgentToolCallStatus::Succeeded,
            result_json: result_json.clone(),
            provider_request_id: Some(format!("connector-result-{case}")),
            next_request_json: Some(next_request_json.clone()),
        };
        let completion = store.complete_agent_tool(commit.clone()).await.unwrap();
        let AgentToolCompletion::ModelQueued { job, .. } = completion else {
            panic!("a known {case} result must enqueue its continuation");
        };
        assert_eq!(job.request_json, next_request_json);

        let replay = store.complete_agent_tool(commit).await.unwrap();
        assert!(matches!(replay, AgentToolCompletion::ModelQueued { .. }));
        let detail = store
            .agent_turn_detail_for_actor(&owner_authz(), "session-alpha", &turn_id)
            .await
            .unwrap();
        assert_eq!(detail.calls.len(), 1);
        assert_eq!(detail.calls[0].status, AgentToolCallStatus::Succeeded);
        assert_eq!(detail.calls[0].output.as_ref(), Some(&result_json));
        assert_ne!(detail.calls[0].status, AgentToolCallStatus::OutcomeUnknown);
    }
}

#[tokio::test]
async fn known_agent_tool_result_without_a_continuation_terminalizes_as_known() {
    let store = created_owned_session_store().await;
    store
        .start_turn_and_enqueue_agent_for_actor(
            &owner_authz(),
            "session-alpha",
            StartTurnRequest {
                turn_id: "turn-agent-tool-no-continuation".into(),
                user_message: "Inspect the workspace even if continuation encoding fails".into(),
                expected_sequence: 1,
            },
            "agent-tool-no-continuation-start",
            agent_turn_spec(
                "agent-tool-no-continuation",
                "turn-agent-tool-no-continuation",
            ),
        )
        .await
        .unwrap();
    let AgentModelClaimOutcome::Claimed(job) = store
        .claim_next_agent_model(&test_agent_manifest())
        .await
        .unwrap()
    else {
        panic!("the initial model job must be claimable");
    };
    let call = agent_tool_call_spec("agent-call-tool-no-continuation", PolicyDecision::Allow);
    store
        .complete_agent_model_success(AgentModelSuccessCommit {
            job_id: job.id,
            response_json: agent_tool_response_json(&call),
            resolution: AgentModelResolution::ToolCall { call: call.clone() },
        })
        .await
        .unwrap();
    let AgentToolClaimOutcome::Claimed(work) = store
        .claim_next_agent_tool(&test_agent_manifest())
        .await
        .unwrap()
    else {
        panic!("the admitted tool must be claimable");
    };
    assert_eq!(work.call.call_id, call.call_id);

    let result_json = json!({"entries": ["Cargo.toml", "crates"]});
    let commit = AgentToolCompletionCommit {
        call_id: call.call_id.clone(),
        status: AgentToolCallStatus::Succeeded,
        result_json: result_json.clone(),
        provider_request_id: Some("connector-known-no-continuation".into()),
        next_request_json: None,
    };
    let completed = store.complete_agent_tool(commit.clone()).await.unwrap();
    let AgentToolCompletion::Terminal(terminal) = completed else {
        panic!("a missing continuation must terminalize the known tool result");
    };
    assert!(!terminal.replayed);
    assert_eq!(terminal.agent.status, AgentTurnStatus::Failed);
    assert_eq!(
        terminal
            .agent
            .last_error_json
            .as_ref()
            .and_then(|error| error.get("code"))
            .and_then(Value::as_str),
        Some("continuation_unavailable")
    );
    assert_eq!(terminal.session.status, SessionStatus::NeedsAttention);
    assert_eq!(terminal.turn.status, SessionTurnStatus::Interrupted);
    let detail = store
        .agent_turn_detail_for_actor(
            &owner_authz(),
            "session-alpha",
            "turn-agent-tool-no-continuation",
        )
        .await
        .unwrap();
    assert_eq!(detail.calls.len(), 1);
    assert_eq!(detail.calls[0].status, AgentToolCallStatus::Succeeded);
    assert_eq!(detail.calls[0].output.as_ref(), Some(&result_json));
    assert_ne!(
        detail.calls[0].status,
        AgentToolCallStatus::OutcomeUnknown,
        "a missing continuation must not erase a known connector outcome"
    );
    assert!(matches!(
        store
            .claim_next_agent_model(&test_agent_manifest())
            .await
            .unwrap(),
        AgentModelClaimOutcome::NotAvailable
    ));

    let replay = store.complete_agent_tool(commit.clone()).await.unwrap();
    let AgentToolCompletion::Terminal(replay) = replay else {
        panic!("the terminal known result must be replayable");
    };
    assert!(replay.replayed);
    assert_eq!(replay.agent, terminal.agent);

    let conflicting_replay = store
        .complete_agent_tool(AgentToolCompletionCommit {
            next_request_json: Some(json!({
                "messages": [{"role": "user", "content": "unused terminal replay"}],
            })),
            ..commit.clone()
        })
        .await;
    assert!(matches!(
        conflicting_replay,
        Err(StorageError::InvalidAgentTransition(message))
            if message.contains("durable continuation request")
    ));

    let exact_replay_after_conflict = store.complete_agent_tool(commit).await.unwrap();
    assert!(matches!(
        exact_replay_after_conflict,
        AgentToolCompletion::Terminal(completion) if completion.replayed
    ));
}

#[tokio::test]
async fn terminal_agent_tool_replay_binds_its_unused_continuation_request() {
    let store = created_owned_session_store().await;
    store
        .start_turn_and_enqueue_agent_for_actor(
            &owner_authz(),
            "session-alpha",
            StartTurnRequest {
                turn_id: "turn-agent-terminal-request-replay".into(),
                user_message: "Reach the tool result boundary with an encoded continuation".into(),
                expected_sequence: 1,
            },
            "agent-terminal-request-replay-start",
            agent_turn_spec(
                "agent-terminal-request-replay",
                "turn-agent-terminal-request-replay",
            ),
        )
        .await
        .unwrap();

    let large_result = json!({"data": "x".repeat(65_500)});
    for ordinal in 1..=2 {
        let AgentModelClaimOutcome::Claimed(job) = store
            .claim_next_agent_model(&test_agent_manifest())
            .await
            .unwrap()
        else {
            panic!("large-result model step {ordinal} must be claimable");
        };
        let call = agent_tool_call_spec(
            &format!("agent-call-terminal-request-{ordinal}"),
            PolicyDecision::Allow,
        );
        store
            .complete_agent_model_success(AgentModelSuccessCommit {
                job_id: job.id,
                response_json: agent_tool_response_json(&call),
                resolution: AgentModelResolution::ToolCall { call: call.clone() },
            })
            .await
            .unwrap();
        let AgentToolClaimOutcome::Claimed(_) = store
            .claim_next_agent_tool(&test_agent_manifest())
            .await
            .unwrap()
        else {
            panic!("large-result tool {ordinal} must be claimable");
        };
        let completion = store
            .complete_agent_tool(AgentToolCompletionCommit {
                call_id: call.call_id,
                status: AgentToolCallStatus::Succeeded,
                result_json: large_result.clone(),
                provider_request_id: Some(format!("terminal-request-{ordinal}")),
                next_request_json: Some(test_agent_request(json!({
                    "messages": [{
                        "role": "tool",
                        "content": format!("large result {ordinal}"),
                        "tool_call_id": call.provider_call_id,
                    }],
                }))),
            })
            .await
            .unwrap();
        assert!(matches!(
            completion,
            AgentToolCompletion::ModelQueued { .. }
        ));
    }

    let AgentModelClaimOutcome::Claimed(job) = store
        .claim_next_agent_model(&test_agent_manifest())
        .await
        .unwrap()
    else {
        panic!("the terminal tool model step must be claimable");
    };
    let call = agent_tool_call_spec("agent-call-terminal-request-3", PolicyDecision::Allow);
    store
        .complete_agent_model_success(AgentModelSuccessCommit {
            job_id: job.id,
            response_json: agent_tool_response_json(&call),
            resolution: AgentModelResolution::ToolCall { call: call.clone() },
        })
        .await
        .unwrap();
    let AgentToolClaimOutcome::Claimed(_) = store
        .claim_next_agent_tool(&test_agent_manifest())
        .await
        .unwrap()
    else {
        panic!("the terminal tool must be claimable");
    };
    let next_request_json = test_agent_request(json!({
        "messages": [{
            "role": "tool",
            "content": "this continuation is bounded but must not be queued",
            "tool_call_id": call.provider_call_id,
        }],
    }));
    let commit = AgentToolCompletionCommit {
        call_id: call.call_id,
        status: AgentToolCallStatus::Succeeded,
        result_json: json!({"data": "y".repeat(100)}),
        provider_request_id: Some("terminal-request-3".into()),
        next_request_json: Some(next_request_json.clone()),
    };
    let completed = store.complete_agent_tool(commit.clone()).await.unwrap();
    let AgentToolCompletion::Terminal(terminal) = completed else {
        panic!("the cumulative tool-result limit must terminalize the completion");
    };
    assert!(!terminal.replayed);
    assert_eq!(
        terminal
            .agent
            .last_error_json
            .as_ref()
            .and_then(|error| error.get("code"))
            .and_then(Value::as_str),
        Some("tool_result_bytes_limit_reached")
    );

    let exact_replay = store.complete_agent_tool(commit.clone()).await.unwrap();
    assert!(matches!(
        exact_replay,
        AgentToolCompletion::Terminal(completion) if completion.replayed
    ));

    for conflicting_request in [
        None,
        Some(json!({
            "messages": [{"role": "user", "content": "different continuation"}],
        })),
    ] {
        let mut conflicting_commit = commit.clone();
        conflicting_commit.next_request_json = conflicting_request;
        assert!(matches!(
            store.complete_agent_tool(conflicting_commit).await,
            Err(StorageError::InvalidAgentTransition(message))
                if message.contains("durable continuation request")
        ));
    }

    let exact_replay_after_conflicts = store.complete_agent_tool(commit).await.unwrap();
    assert!(matches!(
        exact_replay_after_conflicts,
        AgentToolCompletion::Terminal(completion) if completion.replayed
    ));
    store.verify_integrity().await.unwrap();
}

#[tokio::test]
async fn policy_denial_without_a_continuation_persists_the_known_denial() {
    let store = created_owned_session_store().await;
    store
        .start_turn_and_enqueue_agent_for_actor(
            &owner_authz(),
            "session-alpha",
            StartTurnRequest {
                turn_id: "turn-agent-deny-no-continuation".into(),
                user_message: "Attempt a locally denied operation".into(),
                expected_sequence: 1,
            },
            "agent-deny-no-continuation-start",
            agent_turn_spec(
                "agent-deny-no-continuation",
                "turn-agent-deny-no-continuation",
            ),
        )
        .await
        .unwrap();
    let AgentModelClaimOutcome::Claimed(job) = store
        .claim_next_agent_model(&test_agent_manifest())
        .await
        .unwrap()
    else {
        panic!("the initial model job must be claimable");
    };
    let call = agent_tool_call_spec("agent-call-deny-no-continuation", PolicyDecision::Deny);
    let result_json = json!({
        "code": "policy_denied",
        "message": "the call is denied by local policy",
    });
    let commit = AgentModelSuccessCommit {
        job_id: job.id,
        response_json: agent_tool_response_json(&call),
        resolution: AgentModelResolution::PolicyDenied {
            call: call.clone(),
            result_json: result_json.clone(),
            next_request_json: None,
        },
    };
    let completed = store
        .complete_agent_model_success(commit.clone())
        .await
        .unwrap();
    let AgentModelCompletion::Terminal(terminal) = completed else {
        panic!("an unavailable denial continuation must terminate the loop");
    };
    assert!(!terminal.replayed);
    assert_eq!(terminal.agent.status, AgentTurnStatus::Failed);
    assert_eq!(terminal.agent.tool_calls, 1);
    assert_eq!(
        terminal
            .agent
            .last_error_json
            .as_ref()
            .and_then(|error| error.get("code"))
            .and_then(Value::as_str),
        Some("continuation_unavailable")
    );
    let detail = store
        .agent_turn_detail_for_actor(
            &owner_authz(),
            "session-alpha",
            "turn-agent-deny-no-continuation",
        )
        .await
        .unwrap();
    assert_eq!(detail.calls.len(), 1);
    assert_eq!(detail.calls[0].status, AgentToolCallStatus::NotDispatched);
    assert_eq!(detail.calls[0].error.as_ref(), Some(&result_json));
    assert!(matches!(
        store
            .claim_next_agent_model(&test_agent_manifest())
            .await
            .unwrap(),
        AgentModelClaimOutcome::NotAvailable
    ));

    let replay = store
        .complete_agent_model_success(commit.clone())
        .await
        .unwrap();
    let AgentModelCompletion::Terminal(replay) = replay else {
        panic!("the terminal policy denial must be replayable");
    };
    assert!(replay.replayed);
    assert_eq!(replay.agent, terminal.agent);

    let mut conflicting = commit;
    let AgentModelResolution::PolicyDenied {
        next_request_json, ..
    } = &mut conflicting.resolution
    else {
        unreachable!("the test commit is a policy denial")
    };
    *next_request_json = Some(json!({
        "messages": [{"role": "user", "content": "different terminal fingerprint"}],
    }));
    assert!(matches!(
        store.complete_agent_model_success(conflicting).await,
        Err(StorageError::InvalidAgentTransition(_))
    ));
}

#[tokio::test]
async fn fifth_policy_denied_proposal_finishes_atomically_without_a_phantom_call() {
    let store = created_owned_session_store().await;
    store
        .start_turn_and_enqueue_agent_for_actor(
            &owner_authz(),
            "session-alpha",
            StartTurnRequest {
                turn_id: "turn-agent-deny-limit".into(),
                user_message: "Keep requesting denied tools until the loop boundary".into(),
                expected_sequence: 1,
            },
            "agent-deny-limit-start",
            agent_turn_spec("agent-deny-limit", "turn-agent-deny-limit"),
        )
        .await
        .unwrap();

    for ordinal in 1..=4 {
        let AgentModelClaimOutcome::Claimed(job) = store
            .claim_next_agent_model(&test_agent_manifest())
            .await
            .unwrap()
        else {
            panic!("denied model step {ordinal} must be claimable");
        };
        let call = agent_tool_call_spec(
            &format!("agent-call-denied-{ordinal}"),
            PolicyDecision::Deny,
        );
        let completion = store
            .complete_agent_model_success(AgentModelSuccessCommit {
                job_id: job.id,
                response_json: agent_tool_response_json(&call),
                resolution: AgentModelResolution::PolicyDenied {
                    call,
                    result_json: json!({
                        "code": "policy_denied",
                        "message": "the tool is denied by local policy",
                    }),
                    next_request_json: Some(test_agent_request(json!({
                        "messages": [{
                            "role": "tool",
                            "content": format!("policy denied call {ordinal}"),
                            "tool_call_id": format!("provider-call-agent-call-denied-{ordinal}"),
                        }],
                    }))),
                },
            })
            .await
            .unwrap();
        let AgentModelCompletion::ToolCall { agent, call } = completion else {
            panic!("the first four denied proposals must queue continuations");
        };
        assert_eq!(agent.status, AgentTurnStatus::WaitingModel);
        assert_eq!(call.status, AgentToolCallStatus::NotDispatched);
    }

    let AgentModelClaimOutcome::Claimed(fifth_job) = store
        .claim_next_agent_model(&test_agent_manifest())
        .await
        .unwrap()
    else {
        panic!("the fifth model step itself is still within the model-step limit");
    };
    let fifth_call = agent_tool_call_spec("agent-call-denied-5", PolicyDecision::Deny);
    let fifth_commit = AgentModelSuccessCommit {
        job_id: fifth_job.id,
        response_json: agent_tool_response_json(&fifth_call),
        resolution: AgentModelResolution::PolicyDenied {
            call: fifth_call,
            result_json: json!({
                "code": "policy_denied",
                "message": "the fifth denied call reaches the tool-call limit",
            }),
            next_request_json: Some(test_agent_request(json!({
                "messages": [{
                    "role": "tool",
                    "content": "the fifth call was denied",
                    "tool_call_id": "provider-call-agent-call-denied-5",
                }],
            }))),
        },
    };
    let completion = store
        .complete_agent_model_success(fifth_commit.clone())
        .await
        .unwrap();
    let AgentModelCompletion::Terminal(terminal) = completion else {
        panic!("the fifth proposal must terminate at the fixed tool-call limit");
    };
    assert!(!terminal.replayed);
    assert_eq!(terminal.agent.status, AgentTurnStatus::Failed);
    assert_eq!(terminal.agent.tool_calls, 4);
    assert_eq!(terminal.session.status, SessionStatus::NeedsAttention);
    assert_eq!(terminal.turn.status, SessionTurnStatus::Interrupted);
    let detail = store
        .agent_turn_detail_for_actor(&owner_authz(), "session-alpha", "turn-agent-deny-limit")
        .await
        .unwrap();
    assert_eq!(detail.calls.len(), 4);
    assert!(
        detail
            .calls
            .iter()
            .all(|call| call.status == AgentToolCallStatus::NotDispatched)
    );

    let replay = store
        .complete_agent_model_success(fifth_commit)
        .await
        .unwrap();
    let AgentModelCompletion::Terminal(replay) = replay else {
        panic!("the fixed-limit terminal completion must be replayable");
    };
    assert!(replay.replayed);
    assert_eq!(replay.agent, terminal.agent);
    assert_eq!(replay.turn, terminal.turn);
}

#[tokio::test]
async fn approval_rejection_without_a_continuation_persists_the_known_rejection() {
    let store = created_owned_session_store().await;
    store
        .start_turn_and_enqueue_agent_for_actor(
            &owner_authz(),
            "session-alpha",
            StartTurnRequest {
                turn_id: "turn-agent-reject-no-continuation".into(),
                user_message: "Propose an operation requiring owner review".into(),
                expected_sequence: 1,
            },
            "agent-reject-no-continuation-start",
            agent_turn_spec(
                "agent-reject-no-continuation",
                "turn-agent-reject-no-continuation",
            ),
        )
        .await
        .unwrap();
    let AgentModelClaimOutcome::Claimed(job) = store
        .claim_next_agent_model(&test_agent_manifest())
        .await
        .unwrap()
    else {
        panic!("the initial model job must be claimable");
    };
    let call = agent_tool_call_spec(
        "agent-call-reject-no-continuation",
        PolicyDecision::RequireApproval,
    );
    store
        .complete_agent_model_success(AgentModelSuccessCommit {
            job_id: job.id,
            response_json: agent_tool_response_json(&call),
            resolution: AgentModelResolution::ToolCall { call: call.clone() },
        })
        .await
        .unwrap();
    let review_context = store
        .agent_review_context_for_actor(
            &owner_authz(),
            "session-alpha",
            "turn-agent-reject-no-continuation",
            &call.call_id,
        )
        .await
        .unwrap();
    assert!(
        review_context
            .rejection_requires_continuation(Some("owner rejected"))
            .unwrap(),
        "the reducer requires a continuation before its encoding is found unavailable"
    );
    let rejection_result =
        protocol::agent_approval_rejected_result(&call.call_id, Some("owner rejected"));
    let commit = AgentReviewCommit {
        call_id: call.call_id.clone(),
        decision: ReviewDecision::Reject,
        note: Some("owner rejected".into()),
        idempotency_key: "agent-reject-no-continuation".into(),
        next_request_json: None,
    };
    let rejected = store
        .review_agent_tool_for_actor(
            &owner_authz(),
            "session-alpha",
            "turn-agent-reject-no-continuation",
            commit.clone(),
        )
        .await
        .unwrap();
    assert!(!rejected.response.replayed);
    assert_eq!(rejected.response.agent.status, AgentTurnStatus::Failed);
    assert_eq!(rejected.response.call.status, AgentToolCallStatus::Rejected);
    assert_eq!(
        rejected.response.call.error.as_ref(),
        Some(&rejection_result)
    );
    assert_ne!(
        rejected.response.call.status,
        AgentToolCallStatus::OutcomeUnknown
    );
    assert_eq!(
        rejected
            .response
            .agent
            .last_error
            .as_ref()
            .and_then(|error| error.get("code"))
            .and_then(Value::as_str),
        Some("continuation_unavailable")
    );
    assert!(rejected.queued_model_job.is_none());
    let terminal = rejected
        .terminal_completion
        .expect("the unavailable continuation must interrupt the Session turn");
    assert!(!terminal.replayed);
    assert_eq!(terminal.session.status, SessionStatus::NeedsAttention);
    assert_eq!(terminal.turn.status, SessionTurnStatus::Interrupted);
    assert!(matches!(
        store
            .claim_next_agent_model(&test_agent_manifest())
            .await
            .unwrap(),
        AgentModelClaimOutcome::NotAvailable
    ));
    assert!(matches!(
        store
            .claim_next_agent_tool(&test_agent_manifest())
            .await
            .unwrap(),
        AgentToolClaimOutcome::NotAvailable
    ));

    let replay = store
        .review_agent_tool_for_actor(
            &owner_authz(),
            "session-alpha",
            "turn-agent-reject-no-continuation",
            commit,
        )
        .await
        .unwrap();
    assert!(replay.response.replayed);
    assert!(replay.queued_model_job.is_none());
    assert!(replay.terminal_completion.unwrap().replayed);
}

#[tokio::test]
async fn agent_rejection_is_owner_bound_idempotent_and_never_dispatches() {
    let store = created_owned_session_store().await;
    let request = StartTurnRequest {
        turn_id: "turn-agent-review".into(),
        user_message: "Propose a guarded local change".into(),
        expected_sequence: 1,
    };
    store
        .start_turn_and_enqueue_agent_for_actor(
            &owner_authz(),
            "session-alpha",
            request,
            "agent-review-start",
            agent_turn_spec("agent-review", "turn-agent-review"),
        )
        .await
        .unwrap();
    let AgentModelClaimOutcome::Claimed(claimed) = store
        .claim_next_agent_model(&test_agent_manifest())
        .await
        .unwrap()
    else {
        panic!("the approval Agent model step must be claimable");
    };
    let call = agent_tool_call_spec("agent-call-review", PolicyDecision::RequireApproval);
    let proposed = store
        .complete_agent_model_success(AgentModelSuccessCommit {
            job_id: claimed.id,
            response_json: agent_tool_response_json(&call),
            resolution: AgentModelResolution::ToolCall { call: call.clone() },
        })
        .await
        .unwrap();
    let AgentModelCompletion::ToolCall {
        agent,
        call: proposed_call,
    } = proposed
    else {
        panic!("a guarded proposal must wait for owner approval");
    };
    assert_eq!(agent.status, AgentTurnStatus::WaitingApproval);
    assert_eq!(proposed_call.status, AgentToolCallStatus::WaitingApproval);
    let context = store
        .agent_review_context_for_actor(
            &owner_authz(),
            "session-alpha",
            "turn-agent-review",
            &call.call_id,
        )
        .await
        .unwrap();
    assert_eq!(context.work.call, *proposed_call);
    assert!(
        context
            .rejection_requires_continuation(Some("not needed"))
            .unwrap()
    );

    let rejection_result =
        protocol::agent_approval_rejected_result(&call.call_id, Some("not needed"));
    let next_request_json = test_agent_request(json!({
        "messages": [
            {"role": "user", "content": "Propose a guarded local change"},
            {
                "role": "tool",
                "content": serde_json::to_string(&rejection_result).unwrap(),
                "tool_call_id": call.provider_call_id,
            }
        ]
    }));
    let review = AgentReviewCommit {
        call_id: call.call_id.clone(),
        decision: ReviewDecision::Reject,
        note: Some("not needed".into()),
        idempotency_key: "agent-review-reject".into(),
        next_request_json: Some(next_request_json.clone()),
    };
    let rejected = store
        .review_agent_tool_for_actor(
            &owner_authz(),
            "session-alpha",
            "turn-agent-review",
            review.clone(),
        )
        .await
        .unwrap();
    assert!(!rejected.response.replayed);
    assert_eq!(
        rejected.response.agent.status,
        AgentTurnStatus::WaitingModel
    );
    assert_eq!(rejected.response.call.status, AgentToolCallStatus::Rejected);
    assert_eq!(
        rejected.response.call.error.as_ref(),
        Some(&rejection_result)
    );
    assert!(rejected.terminal_completion.is_none());
    assert_eq!(
        rejected
            .queued_model_job
            .as_ref()
            .map(|job| &job.request_json),
        Some(&next_request_json)
    );
    assert!(matches!(
        store
            .claim_next_agent_tool(&test_agent_manifest())
            .await
            .unwrap(),
        AgentToolClaimOutcome::NotAvailable
    ));

    let replay = store
        .review_agent_tool_for_actor(
            &owner_authz(),
            "session-alpha",
            "turn-agent-review",
            AgentReviewCommit {
                next_request_json: None,
                ..review.clone()
            },
        )
        .await
        .unwrap();
    assert!(replay.response.replayed);
    assert_eq!(replay.queued_model_job, rejected.queued_model_job);
    let mut conflicting = review;
    conflicting.note = Some("different decision evidence".into());
    assert!(matches!(
        store
            .review_agent_tool_for_actor(
                &owner_authz(),
                "session-alpha",
                "turn-agent-review",
                conflicting,
            )
            .await,
        Err(StorageError::IdempotencyConflict)
    ));
}

#[tokio::test]
async fn agent_rejection_at_result_limit_terminalizes_without_a_continuation_request() {
    let store = created_owned_session_store().await;
    store
        .start_turn_and_enqueue_agent_for_actor(
            &owner_authz(),
            "session-alpha",
            StartTurnRequest {
                turn_id: "turn-agent-reject-limit".into(),
                user_message: "Reach the cumulative tool-result safety boundary".into(),
                expected_sequence: 1,
            },
            "agent-reject-limit-start",
            agent_turn_spec("agent-reject-limit", "turn-agent-reject-limit"),
        )
        .await
        .unwrap();

    let large_result = json!({"data": "x".repeat(65_500)});
    for ordinal in 1..=2 {
        let AgentModelClaimOutcome::Claimed(job) = store
            .claim_next_agent_model(&test_agent_manifest())
            .await
            .unwrap()
        else {
            panic!("large-result model step {ordinal} must be claimable");
        };
        let call = agent_tool_call_spec(
            &format!("agent-call-large-{ordinal}"),
            PolicyDecision::Allow,
        );
        let completion = store
            .complete_agent_model_success(AgentModelSuccessCommit {
                job_id: job.id,
                response_json: agent_tool_response_json(&call),
                resolution: AgentModelResolution::ToolCall { call: call.clone() },
            })
            .await
            .unwrap();
        assert!(matches!(completion, AgentModelCompletion::ToolCall { .. }));
        let AgentToolClaimOutcome::Claimed(work) = store
            .claim_next_agent_tool(&test_agent_manifest())
            .await
            .unwrap()
        else {
            panic!("large-result tool {ordinal} must be claimable");
        };
        assert_eq!(work.call.call_id, call.call_id);
        let completion = store
            .complete_agent_tool(AgentToolCompletionCommit {
                call_id: call.call_id,
                status: AgentToolCallStatus::Succeeded,
                result_json: large_result.clone(),
                provider_request_id: Some(format!("large-result-request-{ordinal}")),
                next_request_json: Some(test_agent_request(json!({
                    "messages": [{
                        "role": "tool",
                        "content": format!("large result {ordinal} committed"),
                        "tool_call_id": call.provider_call_id,
                    }],
                }))),
            })
            .await
            .unwrap();
        assert!(matches!(
            completion,
            AgentToolCompletion::ModelQueued { .. }
        ));
    }

    let AgentModelClaimOutcome::Claimed(job) = store
        .claim_next_agent_model(&test_agent_manifest())
        .await
        .unwrap()
    else {
        panic!("the approval proposal model step must be claimable");
    };
    let call = agent_tool_call_spec(
        "agent-call-reject-at-limit",
        PolicyDecision::RequireApproval,
    );
    store
        .complete_agent_model_success(AgentModelSuccessCommit {
            job_id: job.id,
            response_json: agent_tool_response_json(&call),
            resolution: AgentModelResolution::ToolCall { call: call.clone() },
        })
        .await
        .unwrap();
    let context = store
        .agent_review_context_for_actor(
            &owner_authz(),
            "session-alpha",
            "turn-agent-reject-limit",
            &call.call_id,
        )
        .await
        .unwrap();
    assert!(
        !context.rejection_requires_continuation(None).unwrap(),
        "the exact rejection result must cross the cumulative result limit"
    );
    let review = AgentReviewCommit {
        call_id: call.call_id.clone(),
        decision: ReviewDecision::Reject,
        note: None,
        idempotency_key: "agent-reject-at-limit".into(),
        next_request_json: None,
    };
    let rejected = store
        .review_agent_tool_for_actor(
            &owner_authz(),
            "session-alpha",
            "turn-agent-reject-limit",
            review.clone(),
        )
        .await
        .unwrap();
    assert!(!rejected.response.replayed);
    assert_eq!(rejected.response.agent.status, AgentTurnStatus::Failed);
    assert_eq!(
        rejected
            .response
            .agent
            .last_error
            .as_ref()
            .and_then(|error| error.get("code"))
            .and_then(Value::as_str),
        Some("tool_result_bytes_limit_reached"),
        "an existing result limit must take precedence over continuation availability"
    );
    assert_eq!(rejected.response.call.status, AgentToolCallStatus::Rejected);
    assert_eq!(
        rejected.response.call.error,
        Some(protocol::agent_approval_rejected_result(
            &call.call_id,
            None
        ))
    );
    assert!(rejected.queued_model_job.is_none());
    let terminal = rejected
        .terminal_completion
        .expect("a limit rejection must return its Session interruption");
    assert!(!terminal.replayed);
    assert_eq!(terminal.session.status, SessionStatus::NeedsAttention);
    assert_eq!(terminal.turn.status, SessionTurnStatus::Interrupted);

    let replay = store
        .review_agent_tool_for_actor(
            &owner_authz(),
            "session-alpha",
            "turn-agent-reject-limit",
            review,
        )
        .await
        .unwrap();
    assert!(replay.response.replayed);
    assert!(replay.queued_model_job.is_none());
    assert!(replay.terminal_completion.unwrap().replayed);
}

#[tokio::test]
async fn policy_denial_at_result_limit_persists_an_unemitted_call() {
    let database = TestDatabase::new();
    let store = created_owned_file_session_store(database.path()).await;
    store
        .start_turn_and_enqueue_agent_for_actor(
            &owner_authz(),
            "session-alpha",
            StartTurnRequest {
                turn_id: "turn-agent-policy-deny-result-limit".into(),
                user_message: "Retain a denied proposal that crosses the result limit".into(),
                expected_sequence: 1,
            },
            "agent-policy-deny-result-limit-start",
            agent_turn_spec(
                "agent-policy-deny-result-limit",
                "turn-agent-policy-deny-result-limit",
            ),
        )
        .await
        .unwrap();

    let large_result = json!({"data": "x".repeat(65_500)});
    for ordinal in 1..=2 {
        let AgentModelClaimOutcome::Claimed(job) = store
            .claim_next_agent_model(&test_agent_manifest())
            .await
            .unwrap()
        else {
            panic!("large-result model step {ordinal} must be claimable");
        };
        let call = agent_tool_call_spec(
            &format!("agent-call-policy-limit-large-{ordinal}"),
            PolicyDecision::Allow,
        );
        store
            .complete_agent_model_success(AgentModelSuccessCommit {
                job_id: job.id,
                response_json: agent_tool_response_json(&call),
                resolution: AgentModelResolution::ToolCall { call: call.clone() },
            })
            .await
            .unwrap();
        let AgentToolClaimOutcome::Claimed(_) = store
            .claim_next_agent_tool(&test_agent_manifest())
            .await
            .unwrap()
        else {
            panic!("large-result tool {ordinal} must be claimable");
        };
        assert!(matches!(
            store
                .complete_agent_tool(AgentToolCompletionCommit {
                    call_id: call.call_id,
                    status: AgentToolCallStatus::Succeeded,
                    result_json: large_result.clone(),
                    provider_request_id: Some(format!("policy-limit-request-{ordinal}")),
                    next_request_json: Some(test_agent_request(json!({
                        "messages": [{
                            "role": "tool",
                            "content": format!("large result {ordinal} committed"),
                            "tool_call_id": call.provider_call_id,
                        }],
                    }))),
                })
                .await
                .unwrap(),
            AgentToolCompletion::ModelQueued { .. }
        ));
    }

    let AgentModelClaimOutcome::Claimed(job) = store
        .claim_next_agent_model(&test_agent_manifest())
        .await
        .unwrap()
    else {
        panic!("the policy-denied model step must be claimable");
    };
    let call = agent_tool_call_spec("agent-call-policy-deny-result-limit", PolicyDecision::Deny);
    let result_json = json!({
        "code": "policy_denied",
        "message": "the durable policy denied this call",
    });
    let result_bytes = u64::try_from(serde_json::to_vec(&result_json).unwrap().len()).unwrap();
    let completed = store
        .complete_agent_model_success(AgentModelSuccessCommit {
            job_id: job.id,
            response_json: agent_tool_response_json(&call),
            resolution: AgentModelResolution::PolicyDenied {
                call: call.clone(),
                result_json: result_json.clone(),
                next_request_json: Some(test_agent_request(json!({
                    "messages": [{
                        "role": "tool",
                        "content": "this continuation must not be queued",
                        "tool_call_id": call.provider_call_id,
                    }],
                }))),
            },
        })
        .await
        .unwrap();
    let AgentModelCompletion::Terminal(terminal) = completed else {
        panic!("the cumulative result limit must terminate the Agent");
    };
    assert_eq!(terminal.agent.status, AgentTurnStatus::Failed);
    assert_eq!(terminal.agent.tool_calls, 3);
    assert_eq!(
        terminal
            .agent
            .last_error_json
            .as_ref()
            .and_then(|error| error.get("code"))
            .and_then(Value::as_str),
        Some("tool_result_bytes_limit_reached")
    );
    let detail = store
        .agent_turn_detail_for_actor(
            &owner_authz(),
            "session-alpha",
            "turn-agent-policy-deny-result-limit",
        )
        .await
        .unwrap();
    assert_eq!(detail.calls.len(), 3);
    assert_eq!(detail.calls[2].status, AgentToolCallStatus::NotDispatched);
    assert_eq!(detail.calls[2].error.as_ref(), Some(&result_json));

    let connection = rusqlite::Connection::open(database.path()).unwrap();
    let stored: String = connection
        .query_row(
            r#"SELECT envelope_json FROM agent_execution_events
               WHERE agent_id = 'agent-policy-deny-result-limit'
               ORDER BY sequence DESC LIMIT 1"#,
            [],
            |row| row.get(0),
        )
        .unwrap();
    let envelope = execution::ExecutionFactEnvelope::from_json_slice(stored.as_bytes()).unwrap();
    let execution::ExecutionFactData::WorkflowTransition {
        command:
            workflows::Command::ModelToolProposal {
                disposition:
                    workflows::ProposalDisposition::Deny {
                        result_bytes: stored_bytes,
                    },
            },
        state,
        emitted_result,
        emitted_result_digest,
        ..
    } = envelope.fact.data
    else {
        panic!("the terminal tail must be a denied proposal fact");
    };
    assert_eq!(stored_bytes, result_bytes);
    assert_eq!(state.status(), workflows::AgentStatus::Failed);
    assert_eq!(
        state.terminal_reason(),
        Some(workflows::TerminalReason::ToolResultBytesLimitReached)
    );
    assert_eq!(emitted_result, None);
    assert_eq!(emitted_result_digest, None);
    drop(connection);
    store.verify_integrity().await.unwrap();
}

struct StoredAgentOperationClaim {
    operation_kind: String,
    operation_id: String,
    model_job_id: Option<String>,
    tool_call_id: Option<String>,
    agent_id: String,
    generation: i64,
    holder_id: String,
    phase: String,
    acquired_at: String,
    expires_at: String,
    started_at: Option<String>,
    released_at: Option<String>,
}

fn load_single_agent_operation_claim(
    connection: &rusqlite::Connection,
) -> StoredAgentOperationClaim {
    connection
        .query_row(
            r#"SELECT operation_kind, operation_id, model_job_id, tool_call_id,
                      agent_id, generation, holder_id, phase, acquired_at,
                      expires_at, started_at, released_at
               FROM agent_operation_claims"#,
            [],
            |row| {
                Ok(StoredAgentOperationClaim {
                    operation_kind: row.get(0)?,
                    operation_id: row.get(1)?,
                    model_job_id: row.get(2)?,
                    tool_call_id: row.get(3)?,
                    agent_id: row.get(4)?,
                    generation: row.get(5)?,
                    holder_id: row.get(6)?,
                    phase: row.get(7)?,
                    acquired_at: row.get(8)?,
                    expires_at: row.get(9)?,
                    started_at: row.get(10)?,
                    released_at: row.get(11)?,
                })
            },
        )
        .unwrap()
}

#[tokio::test]
async fn v20_started_model_migrates_to_one_legacy_started_operation_claim() {
    let database = TestDatabase::new();
    let job_id = {
        let store = created_owned_file_session_store(database.path()).await;
        store
            .start_turn_and_enqueue_agent_for_actor(
                &owner_authz(),
                "session-alpha",
                StartTurnRequest {
                    turn_id: "turn-v20-started-model-claim".into(),
                    user_message: "Preserve the in-flight model operation".into(),
                    expected_sequence: 1,
                },
                "v20-started-model-claim-start",
                agent_turn_spec(
                    "agent-v20-started-model-claim",
                    "turn-v20-started-model-claim",
                ),
            )
            .await
            .unwrap();
        let AgentModelClaimOutcome::Claimed(job) = store
            .claim_next_agent_model(&test_agent_manifest())
            .await
            .unwrap()
        else {
            panic!("the model fixture must be started");
        };
        job.id
    };

    let connection = rusqlite::Connection::open(database.path()).unwrap();
    drop_v21_fixture_objects(&connection);
    assert_eq!(
        connection
            .query_row("SELECT MAX(version) FROM schema_migrations", [], |row| {
                row.get::<_, i64>(0)
            })
            .unwrap(),
        20
    );
    drop(connection);

    let migrated = SqliteStore::open(database.path()).await.unwrap();
    migrated.verify_integrity().await.unwrap();
    let connection = rusqlite::Connection::open(database.path()).unwrap();
    let row = load_single_agent_operation_claim(&connection);
    assert_eq!(row.operation_kind, "model");
    assert_eq!(row.operation_id, job_id);
    assert_eq!(row.model_job_id.as_deref(), Some(job_id.as_str()));
    assert_eq!(row.tool_call_id, None);
    assert_eq!(row.agent_id, "agent-v20-started-model-claim");
    assert_eq!(row.generation, 1);
    assert_eq!(row.holder_id, "legacy-v20");
    assert_eq!(row.phase, "started");
    assert_eq!(row.acquired_at, row.expires_at);
    assert_eq!(row.expires_at, row.started_at.unwrap());
    assert_eq!(row.released_at, None);
}

#[tokio::test]
async fn v20_started_tool_migrates_without_claiming_its_terminal_model() {
    let database = TestDatabase::new();
    let call_id = "agent-call-v20-started-tool-claim";
    {
        let store = created_owned_file_session_store(database.path()).await;
        store
            .start_turn_and_enqueue_agent_for_actor(
                &owner_authz(),
                "session-alpha",
                StartTurnRequest {
                    turn_id: "turn-v20-started-tool-claim".into(),
                    user_message: "Preserve the in-flight tool operation".into(),
                    expected_sequence: 1,
                },
                "v20-started-tool-claim-start",
                agent_turn_spec(
                    "agent-v20-started-tool-claim",
                    "turn-v20-started-tool-claim",
                ),
            )
            .await
            .unwrap();
        let AgentModelClaimOutcome::Claimed(job) = store
            .claim_next_agent_model(&test_agent_manifest())
            .await
            .unwrap()
        else {
            panic!("the model fixture must be claimable");
        };
        let call = agent_tool_call_spec(call_id, PolicyDecision::Allow);
        store
            .complete_agent_model_success(AgentModelSuccessCommit {
                job_id: job.id,
                response_json: agent_tool_response_json(&call),
                resolution: AgentModelResolution::ToolCall { call },
            })
            .await
            .unwrap();
        assert!(matches!(
            store
                .claim_next_agent_tool(&test_agent_manifest())
                .await
                .unwrap(),
            AgentToolClaimOutcome::Claimed(_)
        ));
    }

    let connection = rusqlite::Connection::open(database.path()).unwrap();
    drop_v21_fixture_objects(&connection);
    drop(connection);
    let migrated = SqliteStore::open(database.path()).await.unwrap();
    migrated.verify_integrity().await.unwrap();

    let connection = rusqlite::Connection::open(database.path()).unwrap();
    let count: i64 = connection
        .query_row("SELECT COUNT(*) FROM agent_operation_claims", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(count, 1, "the terminal model must not be backfilled");
    let row = load_single_agent_operation_claim(&connection);
    assert_eq!(row.operation_kind, "tool");
    assert_eq!(row.operation_id, call_id);
    assert_eq!(row.model_job_id, None);
    assert_eq!(row.tool_call_id.as_deref(), Some(call_id));
    assert_eq!(row.agent_id, "agent-v20-started-tool-claim");
    assert_eq!(row.generation, 1);
    assert_eq!(row.holder_id, "legacy-v20");
    assert_eq!(row.phase, "started");
    assert_eq!(row.acquired_at, row.expires_at);
    assert_eq!(row.expires_at, row.started_at.unwrap());
    assert_eq!(row.released_at, None);
}

#[tokio::test]
async fn v20_queued_model_migrates_without_an_operation_claim() {
    let database = TestDatabase::new();
    {
        let store = created_owned_file_session_store(database.path()).await;
        store
            .start_turn_and_enqueue_agent_for_actor(
                &owner_authz(),
                "session-alpha",
                StartTurnRequest {
                    turn_id: "turn-v20-queued-model-no-claim".into(),
                    user_message: "Leave queued work unclaimed".into(),
                    expected_sequence: 1,
                },
                "v20-queued-model-no-claim-start",
                agent_turn_spec(
                    "agent-v20-queued-model-no-claim",
                    "turn-v20-queued-model-no-claim",
                ),
            )
            .await
            .unwrap();
    }
    let connection = rusqlite::Connection::open(database.path()).unwrap();
    drop_v21_fixture_objects(&connection);
    drop(connection);
    let migrated = SqliteStore::open(database.path()).await.unwrap();
    migrated.verify_integrity().await.unwrap();
    let connection = rusqlite::Connection::open(database.path()).unwrap();
    assert_eq!(
        connection
            .query_row("SELECT COUNT(*) FROM agent_operation_claims", [], |row| {
                row.get::<_, i64>(0)
            })
            .unwrap(),
        0
    );
}

#[tokio::test]
async fn agent_operation_claims_enforce_binding_generation_and_forward_transitions() {
    let database = TestDatabase::new();
    let job_id = {
        let store = created_owned_file_session_store(database.path()).await;
        store
            .start_turn_and_enqueue_agent_for_actor(
                &owner_authz(),
                "session-alpha",
                StartTurnRequest {
                    turn_id: "turn-operation-claim-contract".into(),
                    user_message: "Exercise the operation claim contract".into(),
                    expected_sequence: 1,
                },
                "operation-claim-contract-start",
                agent_turn_spec(
                    "agent-operation-claim-contract",
                    "turn-operation-claim-contract",
                ),
            )
            .await
            .unwrap()
            .job
            .id
    };
    let connection = rusqlite::Connection::open(database.path()).unwrap();
    connection
        .pragma_update(None, "foreign_keys", true)
        .unwrap();

    assert!(
        connection
            .execute(
                r#"INSERT INTO agent_operation_claims(
                       operation_kind, operation_id, model_job_id, tool_call_id,
                       agent_id, generation, holder_id, phase, acquired_at,
                       expires_at, started_at, released_at
                   ) VALUES ('model', ?1, ?1, NULL, 'agent-wrong-binding', 1,
                             'holder-a', 'prepared', ?2, ?3, NULL, NULL)"#,
                params![
                    job_id,
                    "2026-08-27T00:00:00.000Z",
                    "2026-08-27T00:01:00.000Z"
                ],
            )
            .is_err(),
        "a claim must bind to the operation's Agent"
    );
    assert!(
        connection
            .execute(
                r#"INSERT INTO agent_operation_claims(
                       operation_kind, operation_id, model_job_id, tool_call_id,
                       agent_id, generation, holder_id, phase, acquired_at,
                       expires_at, started_at, released_at
                   ) VALUES ('model', 'different-operation', ?1, NULL,
                             'agent-operation-claim-contract', 1, 'holder-a',
                             'prepared', ?2, ?3, NULL, NULL)"#,
                params![
                    job_id,
                    "2026-08-27T00:00:00.000Z",
                    "2026-08-27T00:01:00.000Z"
                ],
            )
            .is_err(),
        "operation_id must match the selected nullable operation FK"
    );
    assert!(
        connection
            .execute(
                r#"INSERT INTO agent_operation_claims(
                       operation_kind, operation_id, model_job_id, tool_call_id,
                       agent_id, generation, holder_id, phase, acquired_at,
                       expires_at, started_at, released_at
                   ) VALUES ('model', ?1, NULL, NULL,
                             'agent-operation-claim-contract', 1, 'holder-a',
                             'prepared', ?2, ?3, NULL, NULL)"#,
                params![
                    job_id,
                    "2026-08-27T00:00:00.000Z",
                    "2026-08-27T00:01:00.000Z"
                ],
            )
            .is_err(),
        "exactly one operation FK is required"
    );
    connection
        .execute(
            r#"INSERT INTO agent_operation_claims(
                   operation_kind, operation_id, model_job_id, tool_call_id,
                   agent_id, generation, holder_id, phase, acquired_at,
                   expires_at, started_at, released_at
               ) VALUES ('model', ?1, ?1, NULL,
                         'agent-operation-claim-contract', 1, 'holder-a',
                         'prepared', ?2, ?3, NULL, NULL)"#,
            params![
                job_id,
                "2026-08-27T00:00:00.000Z",
                "2026-08-27T00:01:00.000Z"
            ],
        )
        .unwrap();
    assert!(
        connection
            .execute(
                r#"INSERT INTO agent_operation_claims(
                       operation_kind, operation_id, model_job_id, tool_call_id,
                       agent_id, generation, holder_id, phase, acquired_at,
                       expires_at, started_at, released_at
                   ) VALUES ('model', ?1, ?1, NULL,
                             'agent-operation-claim-contract', 2, 'holder-b',
                             'prepared', ?2, ?3, NULL, NULL)"#,
                params![
                    job_id,
                    "2026-08-27T00:00:10.000Z",
                    "2026-08-27T00:01:10.000Z"
                ],
            )
            .is_err(),
        "one operation cannot have two active claims"
    );
    connection
        .execute(
            r#"UPDATE agent_operation_claims
               SET phase = 'released', released_at = ?2
               WHERE operation_kind = 'model' AND operation_id = ?1 AND generation = 1"#,
            params![job_id, "2026-08-27T00:00:20.000Z"],
        )
        .unwrap();
    assert!(
        connection
            .execute(
                r#"INSERT INTO agent_operation_claims(
                       operation_kind, operation_id, model_job_id, tool_call_id,
                       agent_id, generation, holder_id, phase, acquired_at,
                       expires_at, started_at, released_at
                   ) VALUES ('model', ?1, ?1, NULL,
                             'agent-operation-claim-contract', 3, 'holder-c',
                             'prepared', ?2, ?3, NULL, NULL)"#,
                params![
                    job_id,
                    "2026-08-27T00:00:30.000Z",
                    "2026-08-27T00:01:30.000Z"
                ],
            )
            .is_err(),
        "generation must equal the historical maximum plus one"
    );
    connection
        .execute(
            r#"INSERT INTO agent_operation_claims(
                   operation_kind, operation_id, model_job_id, tool_call_id,
                   agent_id, generation, holder_id, phase, acquired_at,
                   expires_at, started_at, released_at
               ) VALUES ('model', ?1, ?1, NULL,
                         'agent-operation-claim-contract', 2, 'holder-b',
                         'prepared', ?2, ?3, NULL, NULL)"#,
            params![
                job_id,
                "2026-08-27T00:00:30.000Z",
                "2026-08-27T00:00:31.000Z"
            ],
        )
        .unwrap();
    assert!(
        connection
            .execute(
                r#"UPDATE agent_operation_claims SET holder_id = 'holder-mutated'
                   WHERE operation_kind = 'model' AND operation_id = ?1 AND generation = 2"#,
                [&job_id],
            )
            .is_err(),
        "claim identity and acquisition fields are immutable"
    );
    connection
        .execute(
            r#"UPDATE agent_operation_claims
               SET phase = 'started', started_at = ?2
               WHERE operation_kind = 'model' AND operation_id = ?1 AND generation = 2"#,
            params![job_id, "2026-08-27T00:02:00.000Z"],
        )
        .unwrap();
    assert!(
        connection
            .execute(
                r#"UPDATE agent_operation_claims
                   SET phase = 'expired', started_at = NULL, released_at = ?2
                   WHERE operation_kind = 'model' AND operation_id = ?1 AND generation = 2"#,
                params![job_id, "2026-08-27T00:02:10.000Z"],
            )
            .is_err(),
        "a started operation can only be released"
    );
    connection
        .execute(
            r#"UPDATE agent_operation_claims
               SET phase = 'released', released_at = ?2
               WHERE operation_kind = 'model' AND operation_id = ?1 AND generation = 2"#,
            params![job_id, "2026-08-27T00:02:10.000Z"],
        )
        .unwrap();
    assert!(
        connection
            .execute(
                r#"DELETE FROM agent_operation_claims
                   WHERE operation_kind = 'model' AND operation_id = ?1 AND generation = 1"#,
                [&job_id],
            )
            .is_err(),
        "claim history is append-only"
    );
    connection
        .execute(
            r#"INSERT INTO agent_operation_claims(
                   operation_kind, operation_id, model_job_id, tool_call_id,
                   agent_id, generation, holder_id, phase, acquired_at,
                   expires_at, started_at, released_at
               ) VALUES ('model', ?1, ?1, NULL,
                         'agent-operation-claim-contract', 3, 'holder-c',
                         'prepared', ?2, ?3, NULL, NULL)"#,
            params![
                job_id,
                "2026-08-27T00:03:00.000Z",
                "2026-08-27T00:04:00.000Z"
            ],
        )
        .unwrap();
    connection
        .execute(
            r#"UPDATE agent_operation_claims
               SET phase = 'expired', released_at = ?2
               WHERE operation_kind = 'model' AND operation_id = ?1 AND generation = 3"#,
            params![job_id, "2026-08-27T00:04:01.000Z"],
        )
        .unwrap();
    drop(connection);

    let reopened = SqliteStore::open(database.path()).await.unwrap();
    reopened.verify_integrity().await.unwrap();
}

#[tokio::test]
async fn prepared_model_claim_keeps_work_queued_until_one_exact_start() {
    let database = TestDatabase::new();
    let store = created_owned_file_session_store(database.path()).await;
    store
        .start_turn_and_enqueue_agent_for_actor(
            &owner_authz(),
            "session-alpha",
            StartTurnRequest {
                turn_id: "turn-prepared-model-boundary".into(),
                user_message: "Prepare before committing the external start".into(),
                expected_sequence: 1,
            },
            "prepared-model-boundary-start",
            agent_turn_spec(
                "agent-prepared-model-boundary",
                "turn-prepared-model-boundary",
            ),
        )
        .await
        .unwrap();
    let AgentModelClaimOutcome::Prepared(prepared) = store
        .prepare_next_agent_model(&test_agent_manifest(), "model-worker-a")
        .await
        .unwrap()
    else {
        panic!("the queued model job must be prepared");
    };
    let prepared = *prepared;
    let AgentModelClaimOutcome::Prepared(replayed_preparation) = store
        .prepare_next_agent_model(&test_agent_manifest(), "model-worker-a")
        .await
        .unwrap()
    else {
        panic!("the same holder must recover its exact prepared claim");
    };
    assert_eq!(*replayed_preparation, prepared);
    assert!(matches!(
        store
            .prepare_next_agent_model(&test_agent_manifest(), "model-worker-b")
            .await
            .unwrap(),
        AgentModelClaimOutcome::NotAvailable
    ));

    let connection = rusqlite::Connection::open(database.path()).unwrap();
    let before: (String, i64, String, i64, String) = connection
        .query_row(
            r#"SELECT job.status, job.attempt, agent.status,
                      (SELECT COUNT(*) FROM agent_run_epochs epoch
                       WHERE epoch.agent_id = agent.id),
                      claim.phase
               FROM agent_model_jobs job
               JOIN agent_turns agent ON agent.id = job.agent_id
               JOIN agent_operation_claims claim
                 ON claim.operation_kind = 'model'
                AND claim.operation_id = job.id
                AND claim.generation = 1
               WHERE job.id = ?1"#,
            [&prepared.job.id],
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
    assert_eq!(
        before,
        (
            "queued".into(),
            0,
            "waiting_model".into(),
            0,
            "prepared".into()
        )
    );
    drop(connection);

    let AgentModelStartOutcome::Started(started) = store
        .start_prepared_agent_model(&prepared.claim, &test_agent_manifest())
        .await
        .unwrap()
    else {
        panic!("the prepared model claim must start");
    };
    let started = *started;
    let AgentModelStartOutcome::Started(replayed) = store
        .start_prepared_agent_model(&prepared.claim, &test_agent_manifest())
        .await
        .unwrap()
    else {
        panic!("the same started claim must replay exactly");
    };
    assert_eq!(*replayed, started);

    let connection = rusqlite::Connection::open(database.path()).unwrap();
    let after: (String, i64, String, i64, String) = connection
        .query_row(
            r#"SELECT job.status, job.attempt, agent.status,
                      (SELECT COUNT(*) FROM agent_run_epochs epoch
                       WHERE epoch.agent_id = agent.id),
                      claim.phase
               FROM agent_model_jobs job
               JOIN agent_turns agent ON agent.id = job.agent_id
               JOIN agent_operation_claims claim
                 ON claim.operation_kind = 'model'
                AND claim.operation_id = job.id
                AND claim.generation = 1
               WHERE job.id = ?1"#,
            [&prepared.job.id],
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
    assert_eq!(
        after,
        (
            "started".into(),
            1,
            "model_running".into(),
            1,
            "started".into()
        )
    );
    drop(connection);
    store.verify_integrity().await.unwrap();
}

#[tokio::test]
async fn prepared_model_crash_expires_without_unknown_and_next_generation_can_start() {
    let database = TestDatabase::new();
    let first_claim = {
        let store = created_owned_file_session_store(database.path()).await;
        store
            .start_turn_and_enqueue_agent_for_actor(
                &owner_authz(),
                "session-alpha",
                StartTurnRequest {
                    turn_id: "turn-prepared-model-recovery".into(),
                    user_message: "Recover a crash before external start".into(),
                    expected_sequence: 1,
                },
                "prepared-model-recovery-start",
                agent_turn_spec(
                    "agent-prepared-model-recovery",
                    "turn-prepared-model-recovery",
                ),
            )
            .await
            .unwrap();
        let AgentModelClaimOutcome::Prepared(prepared) = store
            .prepare_next_agent_model(&test_agent_manifest(), "model-worker-before-crash")
            .await
            .unwrap()
        else {
            panic!("the queued model job must be prepared");
        };
        prepared.claim.clone()
    };

    let reopened = SqliteStore::open(database.path()).await.unwrap();
    assert!(
        reopened
            .recover_started_agent_work()
            .await
            .unwrap()
            .is_empty()
    );
    let connection = rusqlite::Connection::open(database.path()).unwrap();
    let recovered: (String, i64, String, String, i64, i64) = connection
        .query_row(
            r#"SELECT job.status, job.attempt, agent.status, claim.phase,
                      claim.generation,
                      (SELECT COUNT(*) FROM agent_run_epochs epoch
                       WHERE epoch.agent_id = agent.id)
               FROM agent_model_jobs job
               JOIN agent_turns agent ON agent.id = job.agent_id
               JOIN agent_operation_claims claim
                 ON claim.operation_kind = 'model'
                AND claim.operation_id = job.id
               WHERE job.id = ?1"#,
            [&first_claim.operation_id],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                ))
            },
        )
        .unwrap();
    assert_eq!(
        recovered,
        (
            "queued".into(),
            0,
            "waiting_model".into(),
            "expired".into(),
            1,
            0
        )
    );
    drop(connection);
    assert!(matches!(
        reopened
            .start_prepared_agent_model(&first_claim, &test_agent_manifest())
            .await,
        Err(StorageError::ConcurrentModification)
    ));

    let AgentModelClaimOutcome::Prepared(second) = reopened
        .prepare_next_agent_model(&test_agent_manifest(), "model-worker-after-crash")
        .await
        .unwrap()
    else {
        panic!("the expired preparation must be reclaimable");
    };
    assert_eq!(second.claim.generation, 2);
    assert!(matches!(
        reopened
            .start_prepared_agent_model(&second.claim, &test_agent_manifest())
            .await
            .unwrap(),
        AgentModelStartOutcome::Started(_)
    ));
    reopened.verify_integrity().await.unwrap();
}

#[tokio::test]
async fn agent_operation_claim_generation_gap_fails_deep_readiness() {
    let database = TestDatabase::new();
    let job_id = {
        let store = created_owned_file_session_store(database.path()).await;
        store
            .start_turn_and_enqueue_agent_for_actor(
                &owner_authz(),
                "session-alpha",
                StartTurnRequest {
                    turn_id: "turn-operation-claim-gap".into(),
                    user_message: "Reject a claim generation gap".into(),
                    expected_sequence: 1,
                },
                "operation-claim-gap-start",
                agent_turn_spec("agent-operation-claim-gap", "turn-operation-claim-gap"),
            )
            .await
            .unwrap()
            .job
            .id
    };
    let connection = rusqlite::Connection::open(database.path()).unwrap();
    connection
        .execute(
            r#"INSERT INTO agent_operation_claims(
                   operation_kind, operation_id, model_job_id, tool_call_id,
                   agent_id, generation, holder_id, phase, acquired_at,
                   expires_at, started_at, released_at
               ) VALUES ('model', ?1, ?1, NULL, 'agent-operation-claim-gap', 1,
                         'holder-a', 'released', ?2, ?3, NULL, ?4)"#,
            params![
                job_id,
                "2026-08-27T00:00:00.000Z",
                "2026-08-27T00:01:00.000Z",
                "2026-08-27T00:00:10.000Z"
            ],
        )
        .unwrap();
    let next_generation_trigger = stored_trigger_sql(
        &connection,
        "agent_operation_claims_require_next_generation",
    );
    connection
        .execute_batch("DROP TRIGGER agent_operation_claims_require_next_generation;")
        .unwrap();
    connection
        .execute(
            r#"INSERT INTO agent_operation_claims(
                   operation_kind, operation_id, model_job_id, tool_call_id,
                   agent_id, generation, holder_id, phase, acquired_at,
                   expires_at, started_at, released_at
               ) VALUES ('model', ?1, ?1, NULL, 'agent-operation-claim-gap', 3,
                         'holder-c', 'released', ?2, ?3, NULL, ?4)"#,
            params![
                job_id,
                "2026-08-27T00:02:00.000Z",
                "2026-08-27T00:03:00.000Z",
                "2026-08-27T00:02:10.000Z"
            ],
        )
        .unwrap();
    connection.execute_batch(&next_generation_trigger).unwrap();
    drop(connection);

    let error = match SqliteStore::open(database.path()).await {
        Ok(_) => panic!("a non-contiguous operation claim generation must fail startup"),
        Err(error) => error,
    };
    assert!(matches!(error, StorageError::CorruptData(message)
        if message.contains("Agent operation claims are inconsistent")));
}

#[tokio::test]
async fn started_agent_model_becomes_unknown_once_after_restart() {
    let database = TestDatabase::new();
    let job_id = {
        let store = created_owned_file_session_store(database.path()).await;
        store
            .start_turn_and_enqueue_agent_for_actor(
                &owner_authz(),
                "session-alpha",
                StartTurnRequest {
                    turn_id: "turn-agent-recovery".into(),
                    user_message: "Recover an interrupted model call safely".into(),
                    expected_sequence: 1,
                },
                "agent-recovery-start",
                agent_turn_spec("agent-recovery", "turn-agent-recovery"),
            )
            .await
            .unwrap();
        let AgentModelClaimOutcome::Claimed(claimed) = store
            .claim_next_agent_model(&test_agent_manifest())
            .await
            .unwrap()
        else {
            panic!("the recovery fixture must persist a started model checkpoint");
        };
        claimed.id
    };

    let reopened = SqliteStore::open(database.path()).await.unwrap();
    let recovered = reopened.recover_started_agent_work().await.unwrap();
    assert_eq!(recovered.len(), 1);
    assert!(!recovered[0].replayed);
    assert_eq!(recovered[0].agent.status, AgentTurnStatus::NeedsAttention);
    assert_eq!(recovered[0].session.status, SessionStatus::NeedsAttention);
    assert_eq!(recovered[0].turn.status, SessionTurnStatus::Interrupted);
    assert!(matches!(
        recovered[0].event.data,
        SessionEventData::TurnInterrupted { .. }
    ));
    assert!(
        reopened
            .recover_started_agent_work()
            .await
            .unwrap()
            .is_empty()
    );

    reopened
        .resume_session_for_actor(
            &owner_authz(),
            "session-alpha",
            ResumeSessionRequest {
                expected_sequence: 3,
            },
            "resume-agent-recovery",
        )
        .await
        .unwrap();
    let replay = reopened
        .complete_agent_model_failure(AgentModelFailureCommit {
            job_id,
            error_json: json!({
                "code": "model_outcome_unknown_after_restart",
                "message": "the process restarted after the model checkpoint without a trustworthy result",
            }),
            outcome_unknown: true,
        })
        .await
        .unwrap();
    assert!(replay.replayed);
    assert_eq!(replay.agent.status, AgentTurnStatus::NeedsAttention);
    assert_eq!(replay.session.status, SessionStatus::Ready);
    assert_eq!(replay.turn.status, SessionTurnStatus::Interrupted);
    assert!(matches!(
        reopened
            .claim_next_agent_model(&test_agent_manifest())
            .await
            .unwrap(),
        AgentModelClaimOutcome::NotAvailable
    ));
}

#[tokio::test]
async fn v19_started_model_recovers_from_one_honest_legacy_snapshot_without_an_epoch() {
    let database = TestDatabase::new();
    {
        let store = created_owned_file_session_store(database.path()).await;
        store
            .start_turn_and_enqueue_agent_for_actor(
                &owner_authz(),
                "session-alpha",
                StartTurnRequest {
                    turn_id: "turn-agent-legacy-recovery".into(),
                    user_message: "Recover an operation that started before v20".into(),
                    expected_sequence: 1,
                },
                "agent-legacy-recovery-start",
                agent_turn_spec("agent-legacy-recovery", "turn-agent-legacy-recovery"),
            )
            .await
            .unwrap();
        assert!(matches!(
            store
                .claim_next_agent_model(&test_agent_manifest())
                .await
                .unwrap(),
            AgentModelClaimOutcome::Claimed(_)
        ));
    }

    let connection = rusqlite::Connection::open(database.path()).unwrap();
    drop_v20_fixture_objects(&connection);
    drop(connection);

    let migrated = SqliteStore::open(database.path()).await.unwrap();
    let before = migrated
        .agent_execution_explain_for_actor(
            &owner_authz(),
            "session-alpha",
            "turn-agent-legacy-recovery",
        )
        .await
        .unwrap();
    assert_eq!(
        before.history.origin,
        execution::ExecutionHistoryOrigin::LegacySnapshot
    );
    assert!(before.epochs.is_empty());
    assert_eq!(before.facts.len(), 1);
    assert!(
        before
            .history
            .reasons
            .contains(&execution::ExecutionHistoryReason::OutcomePending)
    );

    let recovered = migrated.recover_started_agent_work().await.unwrap();
    assert_eq!(recovered.len(), 1);
    let after = migrated
        .agent_execution_explain_for_actor(
            &owner_authz(),
            "session-alpha",
            "turn-agent-legacy-recovery",
        )
        .await
        .unwrap();
    assert!(after.epochs.is_empty());
    assert_eq!(after.facts.len(), 2);
    assert!(
        after
            .history
            .reasons
            .contains(&execution::ExecutionHistoryReason::OutcomeUnknown)
    );
    migrated.verify_integrity().await.unwrap();
}

fn stored_trigger_sql(connection: &rusqlite::Connection, name: &str) -> String {
    connection
        .query_row(
            "SELECT sql FROM sqlite_schema WHERE type = 'trigger' AND name = ?1",
            [name],
            |row| row.get(0),
        )
        .unwrap_or_else(|error| panic!("missing trigger `{name}`: {error}"))
}

#[tokio::test]
async fn initial_model_request_tampering_fails_reopen_before_claim() {
    let database = TestDatabase::new();
    {
        let store = created_owned_file_session_store(database.path()).await;
        store
            .start_turn_and_enqueue_agent_for_actor(
                &owner_authz(),
                "session-alpha",
                StartTurnRequest {
                    turn_id: "turn-agent-initial-request-binding".into(),
                    user_message: "Bind the initial model request at admission".into(),
                    expected_sequence: 1,
                },
                "agent-initial-request-binding-start",
                agent_turn_spec(
                    "agent-initial-request-binding",
                    "turn-agent-initial-request-binding",
                ),
            )
            .await
            .unwrap();
        store.verify_integrity().await.unwrap();
    }

    let connection = rusqlite::Connection::open(database.path()).unwrap();
    let input_trigger = stored_trigger_sql(&connection, "agent_model_jobs_reject_input_update");
    let forward_trigger =
        stored_trigger_sql(&connection, "agent_model_jobs_enforce_forward_transition");
    connection
        .execute_batch(
            r#"DROP TRIGGER agent_model_jobs_reject_input_update;
               DROP TRIGGER agent_model_jobs_enforce_forward_transition;"#,
        )
        .unwrap();
    let changed_request = test_agent_request(json!({
        "messages": [{"role": "user", "content": "tampered before first claim"}],
    }));
    connection
        .execute(
            r#"UPDATE agent_model_jobs SET request_json = ?1
               WHERE agent_id = 'agent-initial-request-binding' AND step = 1"#,
            [serde_json::to_string(&changed_request).unwrap()],
        )
        .unwrap();
    connection.execute_batch(&input_trigger).unwrap();
    connection.execute_batch(&forward_trigger).unwrap();
    drop(connection);

    let error = match SqliteStore::open(database.path()).await {
        Ok(_) => panic!("an initial request that diverges from admission must fail startup"),
        Err(error) => error,
    };
    assert!(matches!(error, StorageError::CorruptData(message)
            if message.contains("execution origin disagrees")));
}

#[tokio::test]
async fn orphaned_native_continuation_job_fails_reopen() {
    let database = TestDatabase::new();
    let agent_id = "agent-orphaned-native-continuation-job";
    {
        let store = created_owned_file_session_store(database.path()).await;
        store
            .start_turn_and_enqueue_agent_for_actor(
                &owner_authz(),
                "session-alpha",
                StartTurnRequest {
                    turn_id: "turn-orphaned-native-continuation-job".into(),
                    user_message: "Reject a model job without a causative fact".into(),
                    expected_sequence: 1,
                },
                "orphaned-native-continuation-job-start",
                agent_turn_spec(agent_id, "turn-orphaned-native-continuation-job"),
            )
            .await
            .unwrap();
        let AgentModelClaimOutcome::Claimed(job) = store
            .claim_next_agent_model(&test_agent_manifest())
            .await
            .unwrap()
        else {
            panic!("the initial model job must be claimable");
        };
        store
            .complete_agent_model_success(AgentModelSuccessCommit {
                job_id: job.id,
                response_json: agent_final_response_json("terminal response"),
                resolution: AgentModelResolution::Final {
                    assistant_message: "terminal response".into(),
                    provenance: agent_model_provenance(),
                },
            })
            .await
            .unwrap();
        store.verify_integrity().await.unwrap();
    }

    let connection = rusqlite::Connection::open(database.path()).unwrap();
    let current_step_trigger =
        stored_trigger_sql(&connection, "agent_model_jobs_require_current_step");
    connection
        .execute_batch("DROP TRIGGER agent_model_jobs_require_current_step;")
        .unwrap();
    connection
        .execute(
            r#"INSERT INTO agent_model_jobs(
                   id, agent_id, account_id, actor_user_id, actor_membership_revision,
                   session_id, turn_id, step, provider_name, model_name,
                   status, attempt, request_json, response_json, error_json,
                   queued_at, started_at, finished_at
               )
               SELECT 'agent-model-orphaned-native-step-2', agent_id, account_id,
                      actor_user_id, actor_membership_revision, session_id, turn_id,
                      2, provider_name, model_name, 'queued', 0, request_json,
                      NULL, NULL, queued_at, NULL, NULL
               FROM agent_model_jobs
               WHERE agent_id = ?1 AND step = 1"#,
            [agent_id],
        )
        .unwrap();
    connection.execute_batch(&current_step_trigger).unwrap();
    drop(connection);

    let error = match SqliteStore::open(database.path()).await {
        Ok(_) => panic!("a native continuation job without a causative fact must fail startup"),
        Err(error) => error,
    };
    assert!(matches!(error, StorageError::CorruptData(message)
            if message.contains("does not have exactly one continuation request fact")));
}

#[tokio::test]
async fn forged_old_timestamp_legacy_continuation_job_fails_reopen() {
    let database = TestDatabase::new();
    let agent_id = "agent-forged-legacy-continuation-job";
    {
        let store = created_owned_file_session_store(database.path()).await;
        store
            .start_turn_and_enqueue_agent_for_actor(
                &owner_authz(),
                "session-alpha",
                StartTurnRequest {
                    turn_id: "turn-forged-legacy-continuation-job".into(),
                    user_message: "Do not trust a forged legacy queue timestamp".into(),
                    expected_sequence: 1,
                },
                "forged-legacy-continuation-job-start",
                agent_turn_spec(agent_id, "turn-forged-legacy-continuation-job"),
            )
            .await
            .unwrap();
        let AgentModelClaimOutcome::Claimed(job) = store
            .claim_next_agent_model(&test_agent_manifest())
            .await
            .unwrap()
        else {
            panic!("the initial model job must be claimable");
        };
        store
            .complete_agent_model_success(AgentModelSuccessCommit {
                job_id: job.id,
                response_json: agent_final_response_json("legacy terminal response"),
                resolution: AgentModelResolution::Final {
                    assistant_message: "legacy terminal response".into(),
                    provenance: agent_model_provenance(),
                },
            })
            .await
            .unwrap();
    }
    let connection = rusqlite::Connection::open(database.path()).unwrap();
    drop_v20_fixture_objects(&connection);
    drop(connection);
    let migrated = SqliteStore::open(database.path()).await.unwrap();
    migrated.verify_integrity().await.unwrap();
    drop(migrated);

    let connection = rusqlite::Connection::open(database.path()).unwrap();
    let current_step_trigger =
        stored_trigger_sql(&connection, "agent_model_jobs_require_current_step");
    connection
        .execute_batch("DROP TRIGGER agent_model_jobs_require_current_step;")
        .unwrap();
    connection
        .execute(
            r#"INSERT INTO agent_model_jobs(
                   id, agent_id, account_id, actor_user_id, actor_membership_revision,
                   session_id, turn_id, step, provider_name, model_name,
                   status, attempt, request_json, response_json, error_json,
                   queued_at, started_at, finished_at
               )
               SELECT 'agent-model-forged-legacy-step-2', agent_id, account_id,
                      actor_user_id, actor_membership_revision, session_id, turn_id,
                      2, provider_name, model_name, 'queued', 0, request_json,
                      NULL, NULL, '2000-01-01T00:00:00.000Z', NULL, NULL
               FROM agent_model_jobs
               WHERE agent_id = ?1 AND step = 1"#,
            [agent_id],
        )
        .unwrap();
    connection.execute_batch(&current_step_trigger).unwrap();
    drop(connection);

    let error = match SqliteStore::open(database.path()).await {
        Ok(_) => panic!("a backdated legacy continuation job without a fact must fail startup"),
        Err(error) => error,
    };
    assert!(matches!(error, StorageError::CorruptData(message)
            if message.contains("does not have exactly one continuation request fact")));
}

#[tokio::test]
async fn v19_queued_continuation_migrates_without_a_causative_v20_fact() {
    let database = TestDatabase::new();
    let agent_id = "agent-v19-queued-continuation";
    {
        let store = created_owned_file_session_store(database.path()).await;
        store
            .start_turn_and_enqueue_agent_for_actor(
                &owner_authz(),
                "session-alpha",
                StartTurnRequest {
                    turn_id: "turn-v19-queued-continuation".into(),
                    user_message: "Preserve the queued continuation across v20 migration".into(),
                    expected_sequence: 1,
                },
                "v19-queued-continuation-start",
                agent_turn_spec(agent_id, "turn-v19-queued-continuation"),
            )
            .await
            .unwrap();
        let AgentModelClaimOutcome::Claimed(job) = store
            .claim_next_agent_model(&test_agent_manifest())
            .await
            .unwrap()
        else {
            panic!("the initial model job must be claimable");
        };
        let call = agent_tool_call_spec("agent-call-v19-queued-continuation", PolicyDecision::Deny);
        let next_request = test_agent_request(json!({
            "messages": [{
                "role": "tool",
                "content": "policy denied before v20",
                "tool_call_id": call.provider_call_id,
            }],
        }));
        store
            .complete_agent_model_success(AgentModelSuccessCommit {
                job_id: job.id,
                response_json: agent_tool_response_json(&call),
                resolution: AgentModelResolution::PolicyDenied {
                    call,
                    result_json: json!({"code": "policy_denied", "message": "blocked"}),
                    next_request_json: Some(next_request),
                },
            })
            .await
            .unwrap();
    }
    let connection = rusqlite::Connection::open(database.path()).unwrap();
    drop_v20_fixture_objects(&connection);
    drop(connection);

    let migrated = SqliteStore::open(database.path()).await.unwrap();
    migrated.verify_integrity().await.unwrap();
    let detail = migrated
        .agent_turn_detail_for_actor(
            &owner_authz(),
            "session-alpha",
            "turn-v19-queued-continuation",
        )
        .await
        .unwrap();
    assert_eq!(detail.status, AgentTurnStatus::WaitingModel);
    let connection = rusqlite::Connection::open(database.path()).unwrap();
    assert_eq!(
        connection
            .query_row(
                r#"SELECT COUNT(*) FROM agent_model_jobs
                   WHERE agent_id = ?1 AND step = 2 AND status = 'queued'"#,
                [agent_id],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        1
    );
    drop(connection);

    let AgentModelClaimOutcome::Claimed(job) = migrated
        .claim_next_agent_model(&test_agent_manifest())
        .await
        .unwrap()
    else {
        panic!("the migrated legacy continuation must remain claimable");
    };
    assert_eq!(job.step, 2);
    migrated
        .complete_agent_model_success(AgentModelSuccessCommit {
            job_id: job.id,
            response_json: agent_final_response_json("legacy continuation completed"),
            resolution: AgentModelResolution::Final {
                assistant_message: "legacy continuation completed".into(),
                provenance: agent_model_provenance(),
            },
        })
        .await
        .unwrap();
    migrated.verify_integrity().await.unwrap();
    drop(migrated);
    SqliteStore::open(database.path())
        .await
        .unwrap()
        .verify_integrity()
        .await
        .unwrap();
}

#[tokio::test]
async fn tool_continuation_request_pair_tampering_fails_reopen() {
    let database = TestDatabase::new();
    let call_id = "agent-call-continuation-request-binding";
    {
        let store = created_owned_file_session_store(database.path()).await;
        store
            .start_turn_and_enqueue_agent_for_actor(
                &owner_authz(),
                "session-alpha",
                StartTurnRequest {
                    turn_id: "turn-agent-continuation-request-binding".into(),
                    user_message: "Bind the tool continuation request".into(),
                    expected_sequence: 1,
                },
                "agent-continuation-request-binding-start",
                agent_turn_spec(
                    "agent-continuation-request-binding",
                    "turn-agent-continuation-request-binding",
                ),
            )
            .await
            .unwrap();
        let AgentModelClaimOutcome::Claimed(job) = store
            .claim_next_agent_model(&test_agent_manifest())
            .await
            .unwrap()
        else {
            panic!("the initial model job must be claimable");
        };
        let call = agent_tool_call_spec(call_id, PolicyDecision::Allow);
        store
            .complete_agent_model_success(AgentModelSuccessCommit {
                job_id: job.id,
                response_json: agent_tool_response_json(&call),
                resolution: AgentModelResolution::ToolCall { call },
            })
            .await
            .unwrap();
        assert!(matches!(
            store
                .claim_next_agent_tool(&test_agent_manifest())
                .await
                .unwrap(),
            AgentToolClaimOutcome::Claimed(_)
        ));
        let next_request = test_agent_request(json!({
            "messages": [{"role": "tool", "content": "known result", "tool_call_id": "provider-call-agent-call-continuation-request-binding"}],
        }));
        assert!(matches!(
            store
                .complete_agent_tool(AgentToolCompletionCommit {
                    call_id: call_id.into(),
                    status: AgentToolCallStatus::Succeeded,
                    result_json: json!({"ok": true}),
                    provider_request_id: Some("connector-request-binding".into()),
                    next_request_json: Some(next_request),
                })
                .await
                .unwrap(),
            AgentToolCompletion::ModelQueued { .. }
        ));
        store.verify_integrity().await.unwrap();
    }

    let connection = rusqlite::Connection::open(database.path()).unwrap();
    let model_input = stored_trigger_sql(&connection, "agent_model_jobs_reject_input_update");
    let model_forward =
        stored_trigger_sql(&connection, "agent_model_jobs_enforce_forward_transition");
    let tool_copy = stored_trigger_sql(
        &connection,
        "agent_tool_calls_freeze_completion_next_request",
    );
    let tool_forward =
        stored_trigger_sql(&connection, "agent_tool_calls_enforce_forward_transition");
    connection
        .execute_batch(
            r#"DROP TRIGGER agent_model_jobs_reject_input_update;
               DROP TRIGGER agent_model_jobs_enforce_forward_transition;
               DROP TRIGGER agent_tool_calls_freeze_completion_next_request;
               DROP TRIGGER agent_tool_calls_enforce_forward_transition;"#,
        )
        .unwrap();
    let changed_request = test_agent_request(json!({
        "messages": [{"role": "user", "content": "coherently changed continuation"}],
    }));
    let changed_request = serde_json::to_string(&changed_request).unwrap();
    connection
        .execute(
            r#"UPDATE agent_model_jobs SET request_json = ?1
               WHERE agent_id = 'agent-continuation-request-binding' AND step = 2"#,
            [&changed_request],
        )
        .unwrap();
    connection
        .execute(
            r#"UPDATE agent_tool_calls SET completion_next_request_json = ?1
               WHERE call_id = ?2"#,
            params![changed_request, call_id],
        )
        .unwrap();
    connection.execute_batch(&model_input).unwrap();
    connection.execute_batch(&model_forward).unwrap();
    connection.execute_batch(&tool_copy).unwrap();
    connection.execute_batch(&tool_forward).unwrap();
    drop(connection);

    let error = match SqliteStore::open(database.path()).await {
        Ok(_) => panic!("a coherently changed continuation request must fail startup"),
        Err(error) => error,
    };
    assert!(matches!(error, StorageError::CorruptData(message)
            if message.contains("continuation request fact disagrees")));
}

fn replace_queued_agent_model_request(path: &Path, agent_id: &str, step: u32, request: &Value) {
    let connection = rusqlite::Connection::open(path).unwrap();
    let input_trigger = stored_trigger_sql(&connection, "agent_model_jobs_reject_input_update");
    let forward_trigger =
        stored_trigger_sql(&connection, "agent_model_jobs_enforce_forward_transition");
    connection
        .execute_batch(
            r#"DROP TRIGGER agent_model_jobs_reject_input_update;
               DROP TRIGGER agent_model_jobs_enforce_forward_transition;"#,
        )
        .unwrap();
    connection
        .execute(
            "UPDATE agent_model_jobs SET request_json = ?1 WHERE agent_id = ?2 AND step = ?3",
            params![serde_json::to_string(request).unwrap(), agent_id, step],
        )
        .unwrap();
    connection.execute_batch(&input_trigger).unwrap();
    connection.execute_batch(&forward_trigger).unwrap();
}

#[tokio::test]
async fn policy_denied_continuation_request_tampering_fails_reopen() {
    let database = TestDatabase::new();
    {
        let store = created_owned_file_session_store(database.path()).await;
        store
            .start_turn_and_enqueue_agent_for_actor(
                &owner_authz(),
                "session-alpha",
                StartTurnRequest {
                    turn_id: "turn-policy-continuation-binding".into(),
                    user_message: "Bind the policy denial continuation".into(),
                    expected_sequence: 1,
                },
                "policy-continuation-binding-start",
                agent_turn_spec(
                    "agent-policy-continuation-binding",
                    "turn-policy-continuation-binding",
                ),
            )
            .await
            .unwrap();
        let AgentModelClaimOutcome::Claimed(job) = store
            .claim_next_agent_model(&test_agent_manifest())
            .await
            .unwrap()
        else {
            panic!("the initial model job must be claimable");
        };
        let call = agent_tool_call_spec(
            "agent-call-policy-continuation-binding",
            PolicyDecision::Deny,
        );
        let next_request = test_agent_request(json!({
            "messages": [{"role": "tool", "content": "policy denied", "tool_call_id": call.provider_call_id}],
        }));
        assert!(matches!(
            store
                .complete_agent_model_success(AgentModelSuccessCommit {
                    job_id: job.id,
                    response_json: agent_tool_response_json(&call),
                    resolution: AgentModelResolution::PolicyDenied {
                        call,
                        result_json: json!({"code": "policy_denied", "message": "blocked"}),
                        next_request_json: Some(next_request),
                    },
                })
                .await
                .unwrap(),
            AgentModelCompletion::ToolCall { .. }
        ));
        store.verify_integrity().await.unwrap();
    }

    replace_queued_agent_model_request(
        database.path(),
        "agent-policy-continuation-binding",
        2,
        &test_agent_request(json!({
            "messages": [{"role": "user", "content": "changed policy continuation"}],
        })),
    );
    let error = match SqliteStore::open(database.path()).await {
        Ok(_) => panic!("a changed policy-denied continuation must fail startup"),
        Err(error) => error,
    };
    assert!(matches!(error, StorageError::CorruptData(message)
            if message.contains("continuation request fact disagrees")));
}

#[tokio::test]
async fn orphaned_continuation_fact_fails_reopen_even_after_rehash() {
    let database = TestDatabase::new();
    let agent_id = "agent-orphaned-continuation";
    {
        let store = created_owned_file_session_store(database.path()).await;
        store
            .start_turn_and_enqueue_agent_for_actor(
                &owner_authz(),
                "session-alpha",
                StartTurnRequest {
                    turn_id: "turn-orphaned-continuation".into(),
                    user_message: "Keep continuation causality complete".into(),
                    expected_sequence: 1,
                },
                "orphaned-continuation-start",
                agent_turn_spec(agent_id, "turn-orphaned-continuation"),
            )
            .await
            .unwrap();
        let AgentModelClaimOutcome::Claimed(job) = store
            .claim_next_agent_model(&test_agent_manifest())
            .await
            .unwrap()
        else {
            panic!("the initial model job must be claimable");
        };
        let call = agent_tool_call_spec("agent-call-orphaned-continuation", PolicyDecision::Deny);
        let next_request = test_agent_request(json!({
            "messages": [{"role": "tool", "content": "policy denied", "tool_call_id": call.provider_call_id}],
        }));
        store
            .complete_agent_model_success(AgentModelSuccessCommit {
                job_id: job.id,
                response_json: agent_tool_response_json(&call),
                resolution: AgentModelResolution::PolicyDenied {
                    call,
                    result_json: json!({"code": "policy_denied", "message": "blocked"}),
                    next_request_json: Some(next_request),
                },
            })
            .await
            .unwrap();
        store.verify_integrity().await.unwrap();
    }

    let connection = rusqlite::Connection::open(database.path()).unwrap();
    let delete_trigger = stored_trigger_sql(&connection, "agent_model_jobs_reject_delete");
    let event_trigger = stored_trigger_sql(&connection, "agent_execution_events_reject_update");
    let head_trigger =
        stored_trigger_sql(&connection, "agent_execution_heads_enforce_forward_update");
    let stored: String = connection
        .query_row(
            r#"SELECT envelope_json FROM agent_execution_events
               WHERE agent_id = ?1
                 AND json_extract(envelope_json, '$.fact.data.command.command') = 'model_tool_proposal'"#,
            [agent_id],
            |row| row.get(0),
        )
        .unwrap();
    let mut envelope =
        execution::ExecutionFactEnvelope::from_json_slice(stored.as_bytes()).unwrap();
    let execution::ExecutionFactData::WorkflowTransition {
        next_request_digest,
        ..
    } = &mut envelope.fact.data
    else {
        panic!("the continuation fixture must end in a workflow transition");
    };
    assert!(next_request_digest.take().is_some());
    let envelope = execution::ExecutionFactEnvelope::new(envelope.fact).unwrap();
    let envelope_json = String::from_utf8(envelope.canonical_json_bytes().unwrap()).unwrap();
    connection
        .execute_batch(
            r#"DROP TRIGGER agent_model_jobs_reject_delete;
               DROP TRIGGER agent_execution_events_reject_update;
               DROP TRIGGER agent_execution_heads_enforce_forward_update;"#,
        )
        .unwrap();
    connection
        .execute(
            "DELETE FROM agent_model_jobs WHERE agent_id = ?1 AND step = 2",
            [agent_id],
        )
        .unwrap();
    connection
        .execute(
            r#"UPDATE agent_execution_events
               SET fact_digest = ?1, envelope_json = ?2
               WHERE agent_id = ?3 AND sequence = 3"#,
            params![envelope.digest.as_str(), envelope_json, agent_id],
        )
        .unwrap();
    connection
        .execute(
            r#"UPDATE agent_execution_heads
               SET head_hash = ?1,
                   committed_payload_bytes = (
                       SELECT SUM(length(CAST(envelope_json AS BLOB)))
                       FROM agent_execution_events WHERE agent_id = ?2
                   )
               WHERE agent_id = ?2"#,
            params![envelope.digest.as_str(), agent_id],
        )
        .unwrap();
    connection.execute_batch(&delete_trigger).unwrap();
    connection.execute_batch(&event_trigger).unwrap();
    connection.execute_batch(&head_trigger).unwrap();
    drop(connection);

    let error = match SqliteStore::open(database.path()).await {
        Ok(_) => panic!("an orphaned continuation fact must fail startup integrity"),
        Err(error) => error,
    };
    assert!(matches!(error, StorageError::CorruptData(message)
            if message.contains("continuation request fact disagrees")));
}

#[tokio::test]
async fn approval_rejected_continuation_request_tampering_fails_reopen() {
    let database = TestDatabase::new();
    let call_id = "agent-call-review-continuation-binding";
    {
        let store = created_owned_file_session_store(database.path()).await;
        store
            .start_turn_and_enqueue_agent_for_actor(
                &owner_authz(),
                "session-alpha",
                StartTurnRequest {
                    turn_id: "turn-review-continuation-binding".into(),
                    user_message: "Bind the review rejection continuation".into(),
                    expected_sequence: 1,
                },
                "review-continuation-binding-start",
                agent_turn_spec(
                    "agent-review-continuation-binding",
                    "turn-review-continuation-binding",
                ),
            )
            .await
            .unwrap();
        let AgentModelClaimOutcome::Claimed(job) = store
            .claim_next_agent_model(&test_agent_manifest())
            .await
            .unwrap()
        else {
            panic!("the initial model job must be claimable");
        };
        let call = agent_tool_call_spec(call_id, PolicyDecision::RequireApproval);
        store
            .complete_agent_model_success(AgentModelSuccessCommit {
                job_id: job.id,
                response_json: agent_tool_response_json(&call),
                resolution: AgentModelResolution::ToolCall { call },
            })
            .await
            .unwrap();
        let next_request = test_agent_request(json!({
            "messages": [{"role": "tool", "content": "owner rejected", "tool_call_id": "provider-call-agent-call-review-continuation-binding"}],
        }));
        let reviewed = store
            .review_agent_tool_for_actor(
                &owner_authz(),
                "session-alpha",
                "turn-review-continuation-binding",
                AgentReviewCommit {
                    call_id: call_id.into(),
                    decision: ReviewDecision::Reject,
                    note: Some("reject".into()),
                    idempotency_key: "review-continuation-binding-reject".into(),
                    next_request_json: Some(next_request),
                },
            )
            .await
            .unwrap();
        assert!(reviewed.queued_model_job.is_some());
        store.verify_integrity().await.unwrap();
    }

    replace_queued_agent_model_request(
        database.path(),
        "agent-review-continuation-binding",
        2,
        &test_agent_request(json!({
            "messages": [{"role": "user", "content": "changed review continuation"}],
        })),
    );
    let error = match SqliteStore::open(database.path()).await {
        Ok(_) => panic!("a changed approval-rejected continuation must fail startup"),
        Err(error) => error,
    };
    assert!(matches!(error, StorageError::CorruptData(message)
            if message.contains("continuation request fact disagrees")));
}

#[tokio::test]
async fn semantic_execution_fact_tampering_fails_reopen_even_with_recomputed_hashes() {
    let database = TestDatabase::new();
    {
        let store = created_owned_file_session_store(database.path()).await;
        store
            .start_turn_and_enqueue_agent_for_actor(
                &owner_authz(),
                "session-alpha",
                StartTurnRequest {
                    turn_id: "turn-agent-semantic-tamper".into(),
                    user_message: "Persist a final response for semantic verification".into(),
                    expected_sequence: 1,
                },
                "agent-semantic-tamper-start",
                agent_turn_spec("agent-semantic-tamper", "turn-agent-semantic-tamper"),
            )
            .await
            .unwrap();
        let AgentModelClaimOutcome::Claimed(job) = store
            .claim_next_agent_model(&test_agent_manifest())
            .await
            .unwrap()
        else {
            panic!("the semantic tamper fixture must claim its model");
        };
        store
            .complete_agent_model_success(AgentModelSuccessCommit {
                job_id: job.id,
                response_json: agent_final_response_json("semantic reply"),
                resolution: AgentModelResolution::Final {
                    assistant_message: "semantic reply".into(),
                    provenance: agent_model_provenance(),
                },
            })
            .await
            .unwrap();
    }

    let connection = rusqlite::Connection::open(database.path()).unwrap();
    let event_trigger: String = connection
        .query_row(
            "SELECT sql FROM sqlite_schema WHERE name = 'agent_execution_events_reject_update'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let head_trigger: String = connection
        .query_row(
            "SELECT sql FROM sqlite_schema WHERE name = 'agent_execution_heads_enforce_forward_update'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let stored: String = connection
        .query_row(
            r#"SELECT envelope_json FROM agent_execution_events
               WHERE agent_id = 'agent-semantic-tamper'
                 AND json_extract(envelope_json, '$.fact.data.command.command') = 'model_final'"#,
            [],
            |row| row.get(0),
        )
        .unwrap();
    let mut envelope =
        execution::ExecutionFactEnvelope::from_json_slice(stored.as_bytes()).unwrap();
    let execution::ExecutionFactData::WorkflowTransition {
        command: workflows::Command::ModelFinal { content_bytes },
        ..
    } = &mut envelope.fact.data
    else {
        panic!("the fixture tail must be a model-final fact");
    };
    *content_bytes = 1;
    let envelope = execution::ExecutionFactEnvelope::new(envelope.fact).unwrap();
    let envelope_json = String::from_utf8(envelope.canonical_json_bytes().unwrap()).unwrap();
    connection
        .execute_batch(
            r#"DROP TRIGGER agent_execution_events_reject_update;
               DROP TRIGGER agent_execution_heads_enforce_forward_update;"#,
        )
        .unwrap();
    connection
        .execute(
            r#"UPDATE agent_execution_events
               SET fact_digest = ?1, envelope_json = ?2
               WHERE agent_id = 'agent-semantic-tamper' AND sequence = 3"#,
            params![envelope.digest.as_str(), envelope_json],
        )
        .unwrap();
    connection
        .execute(
            r#"UPDATE agent_execution_heads
               SET head_hash = ?1,
                   committed_payload_bytes = (
                       SELECT SUM(length(CAST(envelope_json AS BLOB)))
                       FROM agent_execution_events
                       WHERE agent_id = 'agent-semantic-tamper'
                   )
               WHERE agent_id = 'agent-semantic-tamper'"#,
            [envelope.digest.as_str()],
        )
        .unwrap();
    connection.execute_batch(&event_trigger).unwrap();
    connection.execute_batch(&head_trigger).unwrap();
    drop(connection);

    let error = match SqliteStore::open(database.path()).await {
        Ok(_) => panic!("semantic fact tampering must fail startup integrity"),
        Err(error) => error,
    };
    assert!(matches!(error, StorageError::CorruptData(message)
            if message.contains("final response")));
}

#[tokio::test]
async fn rejection_reason_tampering_fails_reopen_even_with_recomputed_hashes() {
    let database = TestDatabase::new();
    {
        let store = created_owned_file_session_store(database.path()).await;
        store
            .start_turn_and_enqueue_agent_for_actor(
                &owner_authz(),
                "session-alpha",
                StartTurnRequest {
                    turn_id: "turn-agent-reason-tamper".into(),
                    user_message: "Reject changed deployment authority".into(),
                    expected_sequence: 1,
                },
                "agent-reason-tamper-start",
                agent_turn_spec("agent-reason-tamper", "turn-agent-reason-tamper"),
            )
            .await
            .unwrap();
        let drifted = mutate_test_agent_manifest(|spec| {
            spec.provider.provider_id = "tampered-provider".into();
        });
        assert!(matches!(
            store.claim_next_agent_model(&drifted).await.unwrap(),
            AgentModelClaimOutcome::Rejected(_)
        ));
    }

    let connection = rusqlite::Connection::open(database.path()).unwrap();
    let event_trigger: String = connection
        .query_row(
            "SELECT sql FROM sqlite_schema WHERE name = 'agent_execution_events_reject_update'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let head_trigger: String = connection
        .query_row(
            "SELECT sql FROM sqlite_schema WHERE name = 'agent_execution_heads_enforce_forward_update'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let stored: String = connection
        .query_row(
            r#"SELECT envelope_json FROM agent_execution_events
               WHERE agent_id = 'agent-reason-tamper'
                 AND json_extract(envelope_json, '$.fact.data.command.command') = 'deployment_unavailable'"#,
            [],
            |row| row.get(0),
        )
        .unwrap();
    let mut envelope =
        execution::ExecutionFactEnvelope::from_json_slice(stored.as_bytes()).unwrap();
    let execution::ExecutionFactData::WorkflowTransition { command, .. } = &mut envelope.fact.data
    else {
        panic!("the fixture tail must be a workflow transition");
    };
    *command = workflows::Command::AuthorizationRevoked;
    let envelope = execution::ExecutionFactEnvelope::new(envelope.fact).unwrap();
    let envelope_json = String::from_utf8(envelope.canonical_json_bytes().unwrap()).unwrap();
    connection
        .execute_batch(
            r#"DROP TRIGGER agent_execution_events_reject_update;
               DROP TRIGGER agent_execution_heads_enforce_forward_update;"#,
        )
        .unwrap();
    connection
        .execute(
            r#"UPDATE agent_execution_events
               SET fact_digest = ?1, envelope_json = ?2
               WHERE agent_id = 'agent-reason-tamper' AND sequence = 2"#,
            params![envelope.digest.as_str(), envelope_json],
        )
        .unwrap();
    connection
        .execute(
            r#"UPDATE agent_execution_heads
               SET head_hash = ?1,
                   committed_payload_bytes = (
                       SELECT SUM(length(CAST(envelope_json AS BLOB)))
                       FROM agent_execution_events
                       WHERE agent_id = 'agent-reason-tamper'
                   )
               WHERE agent_id = 'agent-reason-tamper'"#,
            [envelope.digest.as_str()],
        )
        .unwrap();
    connection.execute_batch(&event_trigger).unwrap();
    connection.execute_batch(&head_trigger).unwrap();
    drop(connection);

    let error = match SqliteStore::open(database.path()).await {
        Ok(_) => panic!("rejection reason tampering must fail startup integrity"),
        Err(error) => error,
    };
    assert!(matches!(error, StorageError::CorruptData(message)
            if message.contains("non-release operation fact disagrees")));
}

#[tokio::test]
async fn terminal_proposal_disposition_tampering_fails_with_recomputed_hashes() {
    let database = TestDatabase::new();
    {
        let store = created_owned_file_session_store(database.path()).await;
        store
            .start_turn_and_enqueue_agent_for_actor(
                &owner_authz(),
                "session-alpha",
                StartTurnRequest {
                    turn_id: "turn-agent-proposal-tamper".into(),
                    user_message: "Reach a terminal proposal boundary".into(),
                    expected_sequence: 1,
                },
                "agent-proposal-tamper-start",
                agent_turn_spec("agent-proposal-tamper", "turn-agent-proposal-tamper"),
            )
            .await
            .unwrap();
        for ordinal in 1..=5 {
            let AgentModelClaimOutcome::Claimed(job) = store
                .claim_next_agent_model(&test_agent_manifest())
                .await
                .unwrap()
            else {
                panic!("denied model step {ordinal} must be claimable");
            };
            let call = agent_tool_call_spec(
                &format!("agent-call-proposal-tamper-{ordinal}"),
                PolicyDecision::Deny,
            );
            let completion = store
                .complete_agent_model_success(AgentModelSuccessCommit {
                    job_id: job.id,
                    response_json: agent_tool_response_json(&call),
                    resolution: AgentModelResolution::PolicyDenied {
                        call: call.clone(),
                        result_json: json!({
                            "code": "policy_denied",
                            "message": format!("denied proposal {ordinal}"),
                        }),
                        next_request_json: Some(test_agent_request(json!({
                            "messages": [{
                                "role": "tool",
                                "content": format!("denied proposal {ordinal}"),
                                "tool_call_id": call.provider_call_id,
                            }],
                        }))),
                    },
                })
                .await
                .unwrap();
            if ordinal < 5 {
                assert!(matches!(completion, AgentModelCompletion::ToolCall { .. }));
            } else {
                assert!(matches!(completion, AgentModelCompletion::Terminal(_)));
            }
        }
    }

    let connection = rusqlite::Connection::open(database.path()).unwrap();
    let event_trigger: String = connection
        .query_row(
            "SELECT sql FROM sqlite_schema WHERE name = 'agent_execution_events_reject_update'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let head_trigger: String = connection
        .query_row(
            "SELECT sql FROM sqlite_schema WHERE name = 'agent_execution_heads_enforce_forward_update'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let (sequence, stored): (i64, String) = connection
        .query_row(
            r#"SELECT sequence, envelope_json FROM agent_execution_events
               WHERE agent_id = 'agent-proposal-tamper'
                 AND json_extract(envelope_json, '$.fact.data.command.command') = 'model_tool_proposal'
               ORDER BY sequence DESC LIMIT 1"#,
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    let mut envelope =
        execution::ExecutionFactEnvelope::from_json_slice(stored.as_bytes()).unwrap();
    let execution::ExecutionFactData::WorkflowTransition { command, .. } = &mut envelope.fact.data
    else {
        panic!("the fixture tail must be a workflow transition");
    };
    *command = workflows::Command::ModelToolProposal {
        disposition: workflows::ProposalDisposition::Allow,
    };
    let envelope = execution::ExecutionFactEnvelope::new(envelope.fact).unwrap();
    let envelope_json = String::from_utf8(envelope.canonical_json_bytes().unwrap()).unwrap();
    connection
        .execute_batch(
            r#"DROP TRIGGER agent_execution_events_reject_update;
               DROP TRIGGER agent_execution_heads_enforce_forward_update;"#,
        )
        .unwrap();
    connection
        .execute(
            r#"UPDATE agent_execution_events
               SET fact_digest = ?1, envelope_json = ?2
               WHERE agent_id = 'agent-proposal-tamper' AND sequence = ?3"#,
            params![envelope.digest.as_str(), envelope_json, sequence],
        )
        .unwrap();
    connection
        .execute(
            r#"UPDATE agent_execution_heads
               SET head_hash = ?1,
                   committed_payload_bytes = (
                       SELECT SUM(length(CAST(envelope_json AS BLOB)))
                       FROM agent_execution_events
                       WHERE agent_id = 'agent-proposal-tamper'
                   )
               WHERE agent_id = 'agent-proposal-tamper'"#,
            [envelope.digest.as_str()],
        )
        .unwrap();
    connection.execute_batch(&event_trigger).unwrap();
    connection.execute_batch(&head_trigger).unwrap();
    drop(connection);

    let error = match SqliteStore::open(database.path()).await {
        Ok(_) => panic!("terminal proposal disposition tampering must fail startup integrity"),
        Err(error) => error,
    };
    assert!(matches!(error, StorageError::CorruptData(message)
            if message.contains("terminal proposal disagrees")));
}

#[tokio::test]
async fn persisted_tool_call_tampering_cannot_diverge_from_the_model_response() {
    let database = TestDatabase::new();
    {
        let store = created_owned_file_session_store(database.path()).await;
        store
            .start_turn_and_enqueue_agent_for_actor(
                &owner_authz(),
                "session-alpha",
                StartTurnRequest {
                    turn_id: "turn-agent-call-tamper".into(),
                    user_message: "Bind the executable call to the model response".into(),
                    expected_sequence: 1,
                },
                "agent-call-tamper-start",
                agent_turn_spec("agent-call-tamper", "turn-agent-call-tamper"),
            )
            .await
            .unwrap();
        let AgentModelClaimOutcome::Claimed(job) = store
            .claim_next_agent_model(&test_agent_manifest())
            .await
            .unwrap()
        else {
            panic!("the tamper fixture must claim its model");
        };
        let call = agent_tool_call_spec("agent-call-input-tamper", PolicyDecision::Allow);
        store
            .complete_agent_model_success(AgentModelSuccessCommit {
                job_id: job.id,
                response_json: agent_tool_response_json(&call),
                resolution: AgentModelResolution::ToolCall { call },
            })
            .await
            .unwrap();
    }

    let connection = rusqlite::Connection::open(database.path()).unwrap();
    let input_trigger: String = connection
        .query_row(
            "SELECT sql FROM sqlite_schema WHERE name = 'agent_tool_calls_reject_input_update'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let forward_trigger: String = connection
        .query_row(
            "SELECT sql FROM sqlite_schema WHERE name = 'agent_tool_calls_enforce_forward_transition'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let changed_arguments = json!({"path": ".", "depth": 3});
    connection
        .execute_batch(
            r#"DROP TRIGGER agent_tool_calls_reject_input_update;
               DROP TRIGGER agent_tool_calls_enforce_forward_transition;"#,
        )
        .unwrap();
    connection
        .execute(
            r#"UPDATE agent_tool_calls
               SET arguments_json = ?1, arguments_digest = ?2
               WHERE call_id = 'agent-call-input-tamper'"#,
            params![
                serde_json::to_string(&changed_arguments).unwrap(),
                tools::arguments_digest(&changed_arguments),
            ],
        )
        .unwrap();
    connection.execute_batch(&input_trigger).unwrap();
    connection.execute_batch(&forward_trigger).unwrap();
    drop(connection);

    let error = match SqliteStore::open(database.path()).await {
        Ok(_) => panic!("a durable call that diverges from its model response must fail startup"),
        Err(error) => error,
    };
    assert!(matches!(error, StorageError::CorruptData(message)
            if message.contains("response disagrees with tool call")));
}

#[tokio::test]
async fn reply_context_is_complete_pair_only_and_stable_at_historical_sequence() {
    let database = TestDatabase::new();
    let store = created_owned_file_session_store(database.path()).await;
    store
        .start_turn_for_actor(
            &owner_authz(),
            "session-alpha",
            StartTurnRequest {
                turn_id: "turn-context-legacy-empty".into(),
                user_message: "legacy user-only turn".into(),
                expected_sequence: 1,
            },
            "context-legacy-empty-start",
        )
        .await
        .unwrap();
    store
        .flush_turn_for_actor(
            &owner_authz(),
            "session-alpha",
            FlushSessionRequest {
                turn_id: "turn-context-legacy-empty".into(),
                assistant_message: None,
                expected_sequence: 2,
            },
            "context-legacy-empty-flush",
        )
        .await
        .unwrap();
    assert!(
        store
            .session_reply_turns_for_actor(&owner_authz(), "session-alpha", 3, 31)
            .await
            .unwrap()
            .is_empty(),
        "a durable assistant-less flush is valid history but not model context"
    );
    let first_request = StartTurnRequest {
        turn_id: "turn-context-first".into(),
        user_message: "remember the first fact".into(),
        expected_sequence: 3,
    };
    store
        .start_turn_and_enqueue_reply_for_actor(
            &owner_authz(),
            "session-alpha",
            first_request,
            "context-first",
            reply_job_spec("reply-context-first", "turn-context-first"),
        )
        .await
        .unwrap();
    assert!(
        store
            .session_reply_turns_for_actor(&owner_authz(), "session-alpha", 3, 31)
            .await
            .unwrap()
            .is_empty()
    );
    let ReplyClaimOutcome::Claimed(_) = store.claim_next_reply().await.unwrap() else {
        panic!("the first context reply must be claimable");
    };
    store
        .complete_reply_success(ReplySuccessCommit {
            job_id: "reply-context-first".into(),
            expected_sequence: 4,
            assistant_message: "the first fact is durable".into(),
            provenance: AssistantReplyProvenance {
                provider_id: "test-provider".into(),
                model: Some("test-model".into()),
                reply_kind: AssistantReplyKind::Model,
            },
            response_json: model_reply_json("the first fact is durable"),
        })
        .await
        .unwrap();
    assert!(
        store
            .session_reply_turns_for_actor(&owner_authz(), "session-alpha", 4, 31)
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        store
            .session_reply_turns_for_actor(&owner_authz(), "session-alpha", 5, 31)
            .await
            .unwrap()
            .is_empty()
    );
    let at_first_flush = store
        .session_reply_turns_for_actor(&owner_authz(), "session-alpha", 6, 31)
        .await
        .unwrap();
    assert_eq!(at_first_flush.len(), 1);
    assert_eq!(at_first_flush[0].id, "turn-context-first");

    store
        .start_turn_and_enqueue_reply_for_actor(
            &owner_authz(),
            "session-alpha",
            StartTurnRequest {
                turn_id: "turn-context-second".into(),
                user_message: "recall it".into(),
                expected_sequence: 6,
            },
            "context-second",
            reply_job_spec("reply-context-second", "turn-context-second"),
        )
        .await
        .unwrap();
    let ReplyClaimOutcome::Claimed(_) = store.claim_next_reply().await.unwrap() else {
        panic!("the second context reply must be claimable");
    };
    store
        .complete_reply_success(ReplySuccessCommit {
            job_id: "reply-context-second".into(),
            expected_sequence: 7,
            assistant_message: "recalled".into(),
            provenance: AssistantReplyProvenance {
                provider_id: "test-provider".into(),
                model: Some("test-model".into()),
                reply_kind: AssistantReplyKind::Model,
            },
            response_json: model_reply_json("recalled"),
        })
        .await
        .unwrap();

    assert_eq!(
        store
            .session_reply_turns_for_actor(&owner_authz(), "session-alpha", 6, 31)
            .await
            .unwrap(),
        at_first_flush
    );
    let latest = store
        .session_reply_turns_for_actor(&owner_authz(), "session-alpha", 9, 31)
        .await
        .unwrap();
    assert_eq!(
        latest
            .iter()
            .map(|turn| turn.id.as_str())
            .collect::<Vec<_>>(),
        ["turn-context-first", "turn-context-second"]
    );
    let connection = rusqlite::Connection::open(database.path()).unwrap();
    let plan = explain_query_plan(
        &connection,
        r#"SELECT turn.id
           FROM session_events AS assistant
           JOIN session_events AS flushed
             ON flushed.session_id = assistant.session_id
            AND flushed.sequence = assistant.sequence + 1
            AND flushed.turn_id = assistant.turn_id
            AND flushed.event_kind = 'turn_flushed'
           JOIN session_turns AS turn
             ON turn.session_id = assistant.session_id
            AND turn.id = assistant.turn_id
           WHERE assistant.session_id = ?1
             AND assistant.sequence < ?2
             AND assistant.event_kind = 'assistant_message'
             AND assistant.turn_id IS NOT NULL
             AND flushed.sequence <= ?2
             AND turn.status = 'flushed'
             AND turn.assistant_message IS NOT NULL
           ORDER BY assistant.sequence DESC LIMIT ?3"#,
        params!["session-alpha", 9_i64, 31_i64],
    );
    assert!(
        plan.contains("session_events_reply_context_idx"),
        "reply context lookup must stay on its bounded partial index: {plan}"
    );
}

#[tokio::test]
async fn reply_start_replays_across_membership_revision_without_reauthorizing_queued_work() {
    let database = TestDatabase::new();
    let store = created_owned_file_session_store(database.path()).await;
    let request = StartTurnRequest {
        turn_id: "turn-revision-replay".into(),
        user_message: "Replay this accepted request after an authority change".into(),
        expected_sequence: 1,
    };
    let original_spec = reply_job_spec("reply-revision-replay", "turn-revision-replay");
    let admitted = store
        .start_turn_and_enqueue_reply_for_actor(
            &owner_authz(),
            "session-alpha",
            request.clone(),
            "reply-revision-replay",
            original_spec,
        )
        .await
        .unwrap();
    assert_eq!(admitted.job.actor_membership_revision.get(), 1);

    bump_test_membership_revision(database.path(), "user-owner");
    let revised_authz = AuthzContext {
        account_id: AccountId::local(),
        user_id: "user-owner".into(),
        membership_role: MembershipRole::Member,
        membership_revision: MembershipRevision::new(2).unwrap(),
        auth_session_id: AuthSessionId::from_persistence("asi_revised_member").unwrap(),
    };
    let expiry = (chrono::Utc::now() + chrono::Duration::hours(1))
        .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    store
        .create_auth_session(AuthSessionCommit {
            authz: revised_authz.clone(),
            session_token_hash: "7".repeat(64),
            csrf_hash: "6".repeat(64),
            expires_at: expiry,
        })
        .await
        .unwrap();
    let replayed = store
        .start_turn_and_enqueue_reply_for_actor(
            &revised_authz,
            "session-alpha",
            request,
            "reply-revision-replay",
            ReplyJobSpec {
                authz: revised_authz.clone(),
                ..reply_job_spec("reply-revision-replay", "turn-revision-replay")
            },
        )
        .await
        .unwrap();
    assert!(replayed.start.replayed);
    assert_eq!(replayed.job, admitted.job);

    let ReplyClaimOutcome::Rejected(rejected) = store.claim_next_reply().await.unwrap() else {
        panic!("the stale persisted revision must be settled without provider execution");
    };
    assert_eq!(rejected.job.status, ReplyJobStatus::Failed);
    assert_eq!(rejected.job.actor_membership_revision.get(), 1);
}

#[tokio::test]
async fn actor_scoped_session_creation_sets_owner_required_by_reply_enqueue() {
    let store = SqliteStore::open(":memory:").await.unwrap();
    bootstrap_test_owner(&store).await;
    let request = alpha_session_request();
    let created = store
        .create_session_for_actor(&owner_authz(), request.clone(), "actor-create-session")
        .await
        .unwrap();
    assert!(!created.replayed);
    assert!(
        store
            .create_session_for_actor(&owner_authz(), request, "actor-create-session")
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
    assert!(matches!(
        store
            .create_session(legacy_request, "legacy-create-after-bootstrap")
            .await,
        Err(StorageError::Sqlite(_))
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
            &owner_authz(),
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
        .session_summary_page_for_actor(&owner_authz(), None, 1)
        .await
        .unwrap();
    assert_eq!(first_page.items[0].id, session_id);
    let second_page = reopened
        .session_summary_page_for_actor(&owner_authz(), first_page.next_cursor.as_deref(), 1)
        .await
        .unwrap();
    assert_eq!(second_page.items[0].id, "zz-normal-session");
    assert!(second_page.next_cursor.is_none());
    assert!(
        reopened
            .list_sessions_for_actor(&owner_authz())
            .await
            .unwrap()
            .iter()
            .any(|session| session.id == session_id)
    );
    let detail = reopened
        .get_session_for_actor(&owner_authz(), &session_id)
        .await
        .unwrap();
    assert_eq!(detail.session.sequence, 2);
    assert_eq!(detail.turns[0].id, turn_id);
    assert_eq!(detail.turns[0].user_message, user_message);
    assert_eq!(
        reopened
            .session_turn_for_actor(&owner_authz(), &session_id, &turn_id)
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
            .session_events_after_for_actor(&owner_authz(), &session_id, 0)
            .await
            .unwrap(),
        detail.events
    );
    let legacy_page = reopened
        .session_event_page_for_actor(&owner_authz(), &session_id, 0, 2)
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
async fn account_scoped_session_and_run_reads_allow_members_and_reject_stale_sessions() {
    let database = TestDatabase::new();
    let store = seeded_file_store(database.path()).await;
    store
        .seed_demo_session("session-ZR-1842", "Checkout API latency", RUN_ID)
        .await
        .unwrap();
    bootstrap_test_owner(&store).await;
    insert_test_member(database.path(), "foreign-user", "foreign");
    activate_test_member_auth(
        database.path(),
        "foreign-user",
        TEST_FOREIGN_AUTH_SESSION_ID,
    );

    let sessions = store.list_sessions_for_actor(&owner_authz()).await.unwrap();
    assert_eq!(sessions.len(), 1);
    let session_id = &sessions[0].id;
    assert_eq!(
        store
            .get_session_for_actor(&owner_authz(), session_id)
            .await
            .unwrap()
            .run_ids,
        vec![RUN_ID]
    );
    assert_eq!(
        store
            .get_session_for_actor(&foreign_authz(), session_id)
            .await
            .unwrap()
            .session
            .id,
        *session_id
    );
    assert!(
        !store
            .session_events_after_for_actor(&foreign_authz(), session_id, 0)
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        store
            .snapshot_for_actor(&owner_authz(), RUN_ID)
            .await
            .unwrap()
            .run
            .id,
        RUN_ID
    );
    assert_eq!(
        store
            .snapshot_for_actor(&foreign_authz(), RUN_ID)
            .await
            .unwrap()
            .run
            .id,
        RUN_ID
    );
    assert_eq!(
        store
            .load_run_for_actor(&foreign_authz(), RUN_ID)
            .await
            .unwrap()
            .snapshot
            .run
            .id,
        RUN_ID
    );
    assert!(
        !store
            .events_after_for_actor(&foreign_authz(), RUN_ID, 0)
            .await
            .unwrap()
            .is_empty()
    );

    set_test_user_status(database.path(), "user-owner", "disabled");
    assert!(matches!(
        store
            .get_session_for_actor(&owner_authz(), session_id)
            .await,
        Err(StorageError::AuthSessionNotFound)
    ));
    assert!(matches!(
        store.snapshot_for_actor(&owner_authz(), RUN_ID).await,
        Err(StorageError::AuthSessionNotFound)
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
                &owner_authz(),
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
            .session_summary_page_for_actor(&owner_authz(), cursor.as_deref(), 50)
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
                .session_summary_page_for_actor(&owner_authz(), None, invalid_limit)
                .await,
            Err(StorageError::InvalidPageLimit { limit, max })
                if limit == invalid_limit && max == protocol::COLLECTION_PAGE_MAX_LIMIT
        ));
    }
    assert!(matches!(
        store
            .session_summary_page_for_actor(&owner_authz(), Some("not-a-cursor"), 50)
            .await,
        Err(StorageError::InvalidPageCursor)
    ));

    insert_test_member(database.path(), "foreign-user", "foreign");
    activate_test_member_auth(
        database.path(),
        "foreign-user",
        TEST_FOREIGN_AUTH_SESSION_ID,
    );
    assert!(matches!(
        store
            .session_summary_page_for_actor(&foreign_authz(), first_owner_cursor.as_deref(), 50,)
            .await,
        Err(StorageError::InvalidPageCursor)
    ));
    assert!(matches!(
        store
            .session_detail_page_for_actor(
                &foreign_authz(),
                "session-page-000",
                Some("not-a-cursor"),
                1,
                Some("not-a-cursor"),
                1,
                Some("not-a-cursor"),
                1,
            )
            .await,
        Err(StorageError::InvalidPageCursor)
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
                &owner_authz(),
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
                &owner_authz(),
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
                &owner_authz(),
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
                &owner_authz(),
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
        .session_detail_page_for_actor(&owner_authz(), "session-tail", None, 1, None, 2, None, 2)
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
            &owner_authz(),
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
                &owner_authz(),
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
            &owner_authz(),
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
                &owner_authz(),
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
                &owner_authz(),
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
                &owner_authz(),
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
                    &owner_authz(),
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
    let future = crate::cursor::encode_session_events(
        "acc_local",
        "user-owner",
        "session-tail",
        sequence + 1,
    )
    .unwrap();
    assert!(matches!(
        store
            .session_detail_page_for_actor(
                &owner_authz(),
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
    activate_test_member_auth(
        database.path(),
        "foreign-user",
        TEST_FOREIGN_AUTH_SESSION_ID,
    );
    assert!(matches!(
        store
            .session_detail_page_for_actor(
                &foreign_authz(),
                "session-tail",
                Some("not-a-cursor"),
                1,
                Some("not-a-cursor"),
                1,
                Some("not-a-cursor"),
                1,
            )
            .await,
        Err(StorageError::InvalidPageCursor)
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
        .bounded_run_for_actor(&owner_authz(), RUN_ID, None, 128)
        .await
        .unwrap();
    assert_eq!(first.snapshot.run.sequence, total as u64);
    assert_eq!(first.events.len(), 128);
    assert_eq!(first.events.first().unwrap().sequence, 131);
    assert_eq!(first.events.last().unwrap().sequence, 258);
    assert!(first.events_page.has_more);
    let first_before = first.events_page.next_before.unwrap();

    let second = store
        .bounded_run_for_actor(&owner_authz(), RUN_ID, Some(&first_before), 128)
        .await
        .unwrap();
    assert_eq!(second.snapshot.run.sequence, total as u64);
    assert_eq!(second.events.first().unwrap().sequence, 3);
    assert_eq!(second.events.last().unwrap().sequence, 130);
    assert!(second.events_page.has_more);
    let second_before = second.events_page.next_before.unwrap();

    let third = store
        .bounded_run_for_actor(&owner_authz(), RUN_ID, Some(&second_before), 128)
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
                .bounded_run_for_actor(&owner_authz(), RUN_ID, None, invalid_limit)
                .await,
            Err(StorageError::InvalidPageLimit { limit, max })
                if limit == invalid_limit && max == protocol::EVENT_PAGE_MAX_LIMIT
        ));
    }
    assert!(matches!(
        store
            .bounded_run_for_actor(&owner_authz(), RUN_ID, Some("not-a-cursor"), 2)
            .await,
        Err(StorageError::InvalidPageCursor)
    ));
    assert!(matches!(
        store
            .bounded_run_for_actor(
                &owner_authz(),
                RUN_ID,
                Some(&(first_before.clone() + "=")),
                2,
            )
            .await,
        Err(StorageError::InvalidPageCursor)
    ));
    let wrong_kind =
        crate::cursor::encode_session_events("acc_local", "user-owner", "session-tail", 2).unwrap();
    assert!(matches!(
        store
            .bounded_run_for_actor(&owner_authz(), RUN_ID, Some(&wrong_kind), 2)
            .await,
        Err(StorageError::InvalidPageCursor)
    ));
    let future =
        crate::cursor::encode_run_events("acc_local", "user-owner", RUN_ID, total as u64 + 1)
            .unwrap();
    assert!(matches!(
        store
            .bounded_run_for_actor(&owner_authz(), RUN_ID, Some(&future), 2)
            .await,
        Err(StorageError::PageCursorBeyondHead { head }) if head == total as u64
    ));
    assert!(matches!(
        store
            .bounded_run_for_actor(&foreign_authz(), RUN_ID, Some("not-a-cursor"), 0)
            .await,
        Err(StorageError::AuthSessionNotFound)
    ));
}

#[tokio::test]
async fn actor_scoped_run_event_pages_are_bounded_contiguous_and_cursor_safe() {
    let total = protocol::EVENT_PAGE_MAX_LIMIT + 2;
    let store = bounded_event_store(total).await;

    let first = store
        .run_event_page_for_actor(&owner_authz(), RUN_ID, 0, protocol::EVENT_PAGE_MAX_LIMIT)
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
            &owner_authz(),
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
            &owner_authz(),
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
            .run_event_page_for_actor(&owner_authz(), RUN_ID, total as u64 + 1, 1)
            .await,
        Err(StorageError::EventCursorBeyondHead {
            after,
            head_sequence,
        }) if after == total as u64 + 1 && head_sequence == total as u64
    ));
    assert!(matches!(
        store
            .run_event_page_for_actor(&owner_authz(), RUN_ID, u64::MAX, 1)
            .await,
        Err(StorageError::EventCursorOutOfRange { after }) if after == u64::MAX
    ));
    for invalid_limit in [0, protocol::EVENT_PAGE_MAX_LIMIT + 1] {
        assert!(matches!(
            store
                .run_event_page_for_actor(&owner_authz(), RUN_ID, 0, invalid_limit)
                .await,
            Err(StorageError::InvalidEventPageLimit { limit, max })
                if limit == invalid_limit && max == protocol::EVENT_PAGE_MAX_LIMIT
        ));
    }

    assert!(matches!(
        store
            .run_event_page_for_actor(&foreign_authz(), RUN_ID, total as u64 + 1, 1)
            .await,
        Err(StorageError::AuthSessionNotFound)
    ));
    assert!(matches!(
        store
            .run_event_page_for_actor(&foreign_authz(), RUN_ID, 0, 0)
            .await,
        Err(StorageError::AuthSessionNotFound)
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
        .session_event_page_for_actor(&owner_authz(), "session-ZR-1842", 0, 1)
        .await
        .unwrap();
    assert_eq!(first.items.len(), 1);
    assert_eq!(first.items[0].sequence, 1);
    assert_eq!(first.next_after, Some(1));
    assert_eq!(first.head_sequence, 2);
    assert!(first.has_more);

    let last = store
        .session_event_page_for_actor(&owner_authz(), "session-ZR-1842", 1, 1)
        .await
        .unwrap();
    assert_eq!(last.items.len(), 1);
    assert_eq!(last.items[0].sequence, 2);
    assert_eq!(last.next_after, None);
    assert_eq!(last.head_sequence, 2);
    assert!(!last.has_more);

    assert!(matches!(
        store
            .session_event_page_for_actor(&owner_authz(), "session-ZR-1842", 3, 1)
            .await,
        Err(StorageError::EventCursorBeyondHead {
            after: 3,
            head_sequence: 2,
        })
    ));
    assert!(matches!(
        store
            .session_event_page_for_actor(&foreign_authz(), "session-ZR-1842", 3, 0)
            .await,
        Err(StorageError::AuthSessionNotFound)
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
    activate_test_member_auth(database.path(), "user-member", "asi_test_member");

    let owner = store
        .create_session_for_actor(
            &owner_authz(),
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
            &member_authz(),
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
            &owner_authz(),
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
            &member_authz(),
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
            .session_turn_for_actor(&owner_authz(), "session-owner-scope", "turn-owner-scope",)
            .await
            .unwrap(),
        owner_turn.turn
    );
    assert!(matches!(
        store
            .session_turn_for_actor(
                &member_authz(),
                "session-owner-scope",
                "unknown-member-turn",
            )
            .await,
        Err(StorageError::SessionTurnNotFound(id)) if id == "unknown-member-turn"
    ));
    assert!(matches!(
        store
            .session_turn_for_actor(
                &owner_authz(),
                "session-owner-scope",
                "unknown-turn",
            )
            .await,
        Err(StorageError::SessionTurnNotFound(id)) if id == "unknown-turn"
    ));
    assert_eq!(
        store
            .get_session_for_actor(&member_authz(), "session-owner-scope")
            .await
            .unwrap()
            .session
            .id,
        "session-owner-scope"
    );
    store.readiness().await.unwrap();
}

#[tokio::test]
async fn actor_scoped_resume_authorizes_before_receipt_replay() {
    let store = created_owned_session_store().await;
    store
        .start_turn_for_actor(
            &owner_authz(),
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
                &foreign_authz(),
                "session-alpha",
                request.clone(),
                "resume-shared-key",
            )
            .await,
        Err(StorageError::AuthSessionNotFound)
    ));
    let resumed = store
        .resume_session_for_actor(
            &owner_authz(),
            "session-alpha",
            request.clone(),
            "resume-shared-key",
        )
        .await
        .unwrap();
    assert!(!resumed.replayed);
    assert!(
        store
            .resume_session_for_actor(
                &owner_authz(),
                "session-alpha",
                request,
                "resume-shared-key",
            )
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
    insert_test_member(database.path(), "user-member", "member");
    activate_test_member_auth(database.path(), "user-member", "asi_test_member");
    let (snapshot, _) = seed_fixture();
    let commit = approved_commit(&snapshot, "actor-review");

    assert_eq!(
        store
            .commit_review_for_actor(&owner_authz(), commit.clone())
            .await
            .unwrap(),
        CommitOutcome::Committed
    );
    assert!(
        store
            .review_receipt_for_actor(&owner_authz(), RUN_ID, "actor-review")
            .await
            .unwrap()
            .is_some()
    );
    assert!(matches!(
        store
            .commit_review_for_actor(&member_authz(), commit.clone())
            .await,
        Err(StorageError::PermissionDenied)
    ));
    assert!(matches!(
        store
            .review_receipt_for_actor(&member_authz(), RUN_ID, "actor-review")
            .await,
        Err(StorageError::PermissionDenied)
    ));
    assert!(matches!(
        store
            .review_receipt_for_actor(&member_authz(), "missing-run", "actor-review")
            .await,
        Err(StorageError::RunNotFound(id)) if id == "missing-run"
    ));
    assert!(matches!(
        store
            .review_receipt_for_actor(&foreign_authz(), RUN_ID, "actor-review")
            .await,
        Err(StorageError::AuthSessionNotFound)
    ));

    set_test_user_status(database.path(), "user-owner", "disabled");
    assert!(matches!(
        store.commit_review_for_actor(&owner_authz(), commit).await,
        Err(StorageError::AuthSessionNotFound)
    ));
    assert_eq!(store.load_run(RUN_ID).await.unwrap().events.len(), 7);
}

#[tokio::test]
async fn queued_reply_is_rejected_when_member_revision_changes_before_claim() {
    let store = SqliteStore::open(":memory:").await.unwrap();
    bootstrap_test_owner(&store).await;
    let member = provision_test_member_for_reply(&store).await;
    store
        .create_session_for_actor(
            &member,
            CreateSessionRequest {
                id: "session-member-before-claim".into(),
                title: "Member disabled before claim".into(),
            },
            "create-member-before-claim",
        )
        .await
        .unwrap();
    store
        .start_turn_and_enqueue_reply_for_actor(
            &member,
            "session-member-before-claim",
            StartTurnRequest {
                turn_id: "turn-member-before-claim".into(),
                user_message: "This provider call must never start".into(),
                expected_sequence: 1,
            },
            "enqueue-member-before-claim",
            ReplyJobSpec {
                id: "reply-member-before-claim".into(),
                authz: member.clone(),
                provider_name: "provider-must-not-run".into(),
                model_name: Some("model-must-not-run".into()),
                request_json: json!({"prompt": "must remain durable only"}),
            },
        )
        .await
        .unwrap();
    let transition = store
        .transition_member(
            &owner_authz(),
            TransitionMemberCommit {
                user_id: member.user_id.clone(),
                expected_revision: member.membership_revision,
                expected_role: MembershipRole::Member,
                expected_status: StoredMembershipStatus::Active,
                role: MembershipRole::Member,
                status: StoredMembershipStatus::Disabled,
            },
        )
        .await
        .unwrap();
    assert!(transition.in_flight.reply_job_ids.is_empty());

    let ReplyClaimOutcome::Rejected(completion) = store.claim_next_reply().await.unwrap() else {
        panic!("stale queued member authority must be rejected at claim");
    };
    assert_eq!(completion.job.status, ReplyJobStatus::Failed);
    assert_eq!(completion.job.attempt, 1);
    assert_eq!(
        completion
            .job
            .error_json
            .as_ref()
            .and_then(|value| value.get("code"))
            .and_then(Value::as_str),
        Some("authorization_revoked")
    );
    assert!(matches!(
        store
            .reply_job_for_actor(&member, "reply-member-before-claim")
            .await,
        Err(StorageError::AuthSessionNotFound)
    ));
}

#[tokio::test]
async fn started_reply_completion_survives_member_revision_change_after_claim() {
    let store = SqliteStore::open(":memory:").await.unwrap();
    bootstrap_test_owner(&store).await;
    let member = provision_test_member_for_reply(&store).await;
    store
        .create_session_for_actor(
            &member,
            CreateSessionRequest {
                id: "session-member-after-claim".into(),
                title: "Member disabled after claim".into(),
            },
            "create-member-after-claim",
        )
        .await
        .unwrap();
    store
        .start_turn_and_enqueue_reply_for_actor(
            &member,
            "session-member-after-claim",
            StartTurnRequest {
                turn_id: "turn-member-after-claim".into(),
                user_message: "This accepted provider call must settle once".into(),
                expected_sequence: 1,
            },
            "enqueue-member-after-claim",
            ReplyJobSpec {
                id: "reply-member-after-claim".into(),
                authz: member.clone(),
                provider_name: "test-provider".into(),
                model_name: Some("test-model".into()),
                request_json: json!({"prompt": "settle after claim"}),
            },
        )
        .await
        .unwrap();
    let ReplyClaimOutcome::Claimed(claimed) = store.claim_next_reply().await.unwrap() else {
        panic!("current member authority must be claimable");
    };
    assert_eq!(claimed.status, ReplyJobStatus::Started);
    let transition = store
        .transition_member(
            &owner_authz(),
            TransitionMemberCommit {
                user_id: member.user_id.clone(),
                expected_revision: member.membership_revision,
                expected_role: MembershipRole::Member,
                expected_status: StoredMembershipStatus::Active,
                role: MembershipRole::Member,
                status: StoredMembershipStatus::Disabled,
            },
        )
        .await
        .unwrap();
    assert_eq!(
        transition.in_flight.reply_job_ids,
        ["reply-member-after-claim"]
    );
    let expected_sequence = store
        .session_summary_for_progress("session-member-after-claim")
        .await
        .unwrap()
        .sequence;
    let commit = ReplySuccessCommit {
        job_id: "reply-member-after-claim".into(),
        expected_sequence,
        assistant_message: "The already-started call settled".into(),
        provenance: AssistantReplyProvenance {
            provider_id: "test-provider".into(),
            model: Some("test-model".into()),
            reply_kind: AssistantReplyKind::Model,
        },
        response_json: model_reply_json("The already-started call settled"),
    };
    let completed = store.complete_reply_success(commit.clone()).await.unwrap();
    assert_eq!(completed.job.status, ReplyJobStatus::Succeeded);
    assert!(!completed.replayed);
    let replayed = store.complete_reply_success(commit).await.unwrap();
    assert!(replayed.replayed);
    assert_eq!(replayed.events, completed.events);
    assert!(matches!(
        store
            .reply_job_for_actor(&member, "reply-member-after-claim")
            .await,
        Err(StorageError::AuthSessionNotFound)
    ));
}

#[tokio::test]
async fn reply_job_for_actor_uses_one_snapshot_across_concurrent_revocation() {
    let database = TestDatabase::new();
    let store = created_owned_file_session_store(database.path()).await;
    store
        .start_turn_and_enqueue_reply_for_actor(
            &owner_authz(),
            "session-alpha",
            StartTurnRequest {
                turn_id: "turn-atomic-reply-read".into(),
                user_message: "Keep the authority and job read in one snapshot".into(),
                expected_sequence: 1,
            },
            "start-atomic-reply-read",
            reply_job_spec("reply-atomic-read", "turn-atomic-reply-read"),
        )
        .await
        .unwrap();

    let authority_observed = Arc::new(Barrier::new(2));
    let allow_job_read = Arc::new(Barrier::new(2));
    let reader_path = database.path().to_owned();
    let reader_context = owner_authz();
    let reader_authority_observed = Arc::clone(&authority_observed);
    let reader_allow_job_read = Arc::clone(&allow_job_read);
    let reader = thread::spawn(move || {
        let mut connection = rusqlite::Connection::open(reader_path).unwrap();
        connection.busy_timeout(Duration::from_secs(5)).unwrap();
        crate::sqlite::query_reply_job_for_actor_with_snapshot_hook(
            &mut connection,
            &reader_context,
            "reply-atomic-read",
            || {
                reader_authority_observed.wait();
                reader_allow_job_read.wait();
            },
        )
    });

    authority_observed.wait();
    assert!(
        store
            .revoke_auth_session(&owner_authz(), &"b".repeat(64))
            .await
            .unwrap()
    );
    assert!(matches!(
        store.claim_next_reply().await.unwrap(),
        ReplyClaimOutcome::Claimed(_)
    ));
    allow_job_read.wait();

    let snapshot_job = reader.join().unwrap().unwrap().unwrap();
    assert_eq!(snapshot_job.status, ReplyJobStatus::Queued);
    assert_eq!(
        store
            .reply_job("reply-atomic-read")
            .await
            .unwrap()
            .unwrap()
            .status,
        ReplyJobStatus::Started
    );
    assert!(matches!(
        store
            .reply_job_for_actor(&owner_authz(), "reply-atomic-read")
            .await,
        Err(StorageError::AuthSessionNotFound)
    ));
}

#[tokio::test]
async fn reply_claim_rechecks_actor_and_interrupts_without_provider_execution() {
    let database = TestDatabase::new();
    let store = created_owned_file_session_store(database.path()).await;
    store
        .start_turn_and_enqueue_reply_for_actor(
            &owner_authz(),
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
async fn exact_reply_start_replays_one_observed_job_without_skipping_the_queue() {
    let store = SqliteStore::open(":memory:").await.unwrap();
    bootstrap_test_owner(&store).await;
    for (session_id, turn_id, job_id) in [
        (
            "session-exact-reply-a",
            "turn-exact-reply-a",
            "reply-exact-a",
        ),
        (
            "session-exact-reply-b",
            "turn-exact-reply-b",
            "reply-exact-b",
        ),
    ] {
        store
            .create_session_for_actor(
                &owner_authz(),
                CreateSessionRequest {
                    id: session_id.into(),
                    title: format!("Exact start for {job_id}"),
                },
                &format!("create-{session_id}"),
            )
            .await
            .unwrap();
        store
            .start_turn_and_enqueue_reply_for_actor(
                &owner_authz(),
                session_id,
                StartTurnRequest {
                    turn_id: turn_id.into(),
                    user_message: format!("Start {job_id} exactly once"),
                    expected_sequence: 1,
                },
                &format!("enqueue-{job_id}"),
                reply_job_spec(job_id, turn_id),
            )
            .await
            .unwrap();
    }

    let observed = store.peek_next_reply().await.unwrap().unwrap();
    assert_eq!(observed.id, "reply-exact-a");
    assert_eq!(observed.status, ReplyJobStatus::Queued);

    let first = store.start_observed_reply(&observed.id).await.unwrap();
    let replayed = store.start_observed_reply(&observed.id).await.unwrap();
    assert_eq!(replayed, first);
    let ReplyClaimOutcome::Claimed(first) = first else {
        panic!("the observed queue head must start");
    };
    assert_eq!(first.id, "reply-exact-a");
    assert_eq!(first.status, ReplyJobStatus::Started);
    assert_eq!(first.attempt, 1);

    let next = store.peek_next_reply().await.unwrap().unwrap();
    assert_eq!(next.id, "reply-exact-b");
    assert_eq!(next.status, ReplyJobStatus::Queued);
    assert_eq!(next.attempt, 0);
    store.verify_integrity().await.unwrap();
}

#[tokio::test]
async fn exact_reply_start_replays_a_committed_authorization_rejection() {
    let database = TestDatabase::new();
    let store = created_owned_file_session_store(database.path()).await;
    store
        .start_turn_and_enqueue_reply_for_actor(
            &owner_authz(),
            "session-alpha",
            StartTurnRequest {
                turn_id: "turn-exact-rejected-reply".into(),
                user_message: "Never reach the provider after revocation".into(),
                expected_sequence: 1,
            },
            "enqueue-exact-rejected-reply",
            reply_job_spec("reply-exact-rejected", "turn-exact-rejected-reply"),
        )
        .await
        .unwrap();
    set_test_user_status(database.path(), "user-owner", "disabled");

    let observed = store.peek_next_reply().await.unwrap().unwrap();
    assert_eq!(observed.id, "reply-exact-rejected");
    let ReplyClaimOutcome::Rejected(first) =
        store.start_observed_reply(&observed.id).await.unwrap()
    else {
        panic!("the revoked actor must be rejected before provider execution");
    };
    assert!(!first.replayed);

    let ReplyClaimOutcome::Rejected(replayed) =
        store.start_observed_reply(&observed.id).await.unwrap()
    else {
        panic!("an ambiguous rejection acknowledgement must replay exactly");
    };
    assert!(replayed.replayed);
    assert_eq!(replayed.job, first.job);
    assert_eq!(replayed.session, first.session);
    assert_eq!(replayed.turn, first.turn);
    assert_eq!(replayed.events, first.events);
    assert!(store.peek_next_reply().await.unwrap().is_none());
}

#[tokio::test]
async fn dispatch_claim_rechecks_owner_and_records_not_dispatched_evidence() {
    let database = TestDatabase::new();
    let store = seeded_file_store(database.path()).await;
    bootstrap_test_owner(&store).await;
    let (snapshot, _) = seed_fixture();
    let review = approved_dispatch_commit(&snapshot, "revoked-dispatch");
    set_test_user_role(database.path(), "user-owner", "member");
    store
        .commit_review_for_actor(&owner_authz(), review.clone())
        .await
        .unwrap();
    bump_test_membership_revision(database.path(), "user-owner");

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
        "initiating_authority_revoked"
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
    store.verify_integrity().await.unwrap();
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
        store
            .commit_review_for_actor(&owner_authz(), commit.clone())
            .await
            .unwrap(),
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
        store
            .commit_review_for_actor(&owner_authz(), commit)
            .await
            .unwrap(),
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
                store.commit_review_for_actor(&owner_authz(), commit).await,
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
        store
            .commit_review_for_actor(&owner_authz(), valid.clone())
            .await
            .unwrap(),
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
        .commit_review_for_actor(
            &owner_authz(),
            approved_dispatch_commit(&snapshot, "immutable-job"),
        )
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
    store
        .commit_review_for_actor(&owner_authz(), review.clone())
        .await
        .unwrap();
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
    store
        .commit_review_for_actor(&owner_authz(), review.clone())
        .await
        .unwrap();
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
    store
        .commit_review_for_actor(&owner_authz(), review.clone())
        .await
        .unwrap();
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
async fn committed_dispatch_completion_replays_the_exact_terminal_ack() {
    let store = seeded_memory_store().await;
    bootstrap_test_owner(&store).await;
    let (snapshot, _) = seed_fixture();
    let review = approved_dispatch_commit(&snapshot, "complete-ack-replay-review");
    store
        .commit_review_for_actor(&owner_authz(), review.clone())
        .await
        .unwrap();
    let start = start_commit(&review.snapshot);
    store.claim_next_dispatch(start.clone()).await.unwrap();
    let completion = completion_commit(&start.snapshot);

    let committed = store.complete_dispatch(completion.clone()).await.unwrap();
    let replayed = store.complete_dispatch(completion.clone()).await.unwrap();

    assert_eq!(replayed, committed);
    let loaded = store.load_run(RUN_ID).await.unwrap();
    assert_eq!(loaded.snapshot, completion.snapshot);
    assert_eq!(loaded.events.len(), 9);
    assert_eq!(loaded.events.last(), Some(&completion.event));
}

#[tokio::test]
async fn committed_dispatch_completion_rejects_conflicting_terminal_acks() {
    let store = seeded_memory_store().await;
    bootstrap_test_owner(&store).await;
    let (snapshot, _) = seed_fixture();
    let review = approved_dispatch_commit(&snapshot, "complete-ack-conflict-review");
    store
        .commit_review_for_actor(&owner_authz(), review.clone())
        .await
        .unwrap();
    let start = start_commit(&review.snapshot);
    store.claim_next_dispatch(start.clone()).await.unwrap();
    let completion = completion_commit(&start.snapshot);
    let committed = store.complete_dispatch(completion.clone()).await.unwrap();

    let mut different_event = completion.clone();
    different_event.event.at = "2026-08-26T01:20:03Z".into();
    assert!(matches!(
        store.complete_dispatch(different_event).await,
        Err(StorageError::IdempotencyConflict)
    ));

    let mut different_result = completion.clone();
    different_result.result_json = serde_json::to_value(ToolOutcome::Failed {
        summary: "A different terminal result".into(),
        error_code: Some("different_result".into()),
    })
    .unwrap();
    assert!(matches!(
        store.complete_dispatch(different_result).await,
        Err(StorageError::IdempotencyConflict)
    ));

    assert_eq!(
        store.dispatch_job("call-local-001").await.unwrap(),
        Some(committed)
    );
    let loaded = store.load_run(RUN_ID).await.unwrap();
    assert_eq!(loaded.snapshot, completion.snapshot);
    assert_eq!(loaded.events.len(), 9);
    assert_eq!(loaded.events.last(), Some(&completion.event));
}

#[tokio::test]
async fn dispatch_storage_rejects_noncanonical_event_and_projection_without_partial_writes() {
    let store = seeded_memory_store().await;
    bootstrap_test_owner(&store).await;
    let (snapshot, _) = seed_fixture();
    let review = approved_dispatch_commit(&snapshot, "canonical-dispatch-review");
    store
        .commit_review_for_actor(&owner_authz(), review.clone())
        .await
        .unwrap();

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
            .commit_review_for_actor(&owner_authz(), review.clone())
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
            .commit_review_for_actor(&owner_authz(), review)
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
    assert_eq!(recovered.result_json, Some(recovery.result_json.clone()));
    assert!(reopened.started_dispatches().await.unwrap().is_empty());
    assert!(reopened.peek_next_dispatch().await.unwrap().is_none());
    let loaded = reopened.load_run(RUN_ID).await.unwrap();
    assert_eq!(loaded.snapshot.run.status, RunStatus::NeedsAttention);
    assert_eq!(loaded.snapshot.run.sequence, 9);
    assert_eq!(loaded.events.last(), Some(&recovery.event));

    let replayed = reopened.recover_started(recovery.clone()).await.unwrap();
    assert_eq!(replayed, recovered);
    let replayed_run = reopened.load_run(RUN_ID).await.unwrap();
    assert_eq!(replayed_run.snapshot, recovery.snapshot);
    assert_eq!(replayed_run.events.len(), 9);
    assert_eq!(replayed_run.events.last(), Some(&recovery.event));

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
        sessions_per_actor: 1,
        sessions_per_account: 1,
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
            &owner_authz(),
            admitted.clone(),
            "create-session-quota-admitted",
        )
        .await
        .unwrap();
    assert!(!created.replayed);

    assert!(matches!(
        store
            .create_session_for_actor(
                &owner_authz(),
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
        .create_session_for_actor(&owner_authz(), admitted, "create-session-quota-admitted")
        .await
        .unwrap();
    assert!(replayed.replayed);
    assert_eq!(replayed.session, created.session);
    assert_eq!(
        store.list_sessions_for_actor(&owner_authz()).await.unwrap(),
        vec![created.session]
    );
}

#[tokio::test]
async fn session_capacity_enforces_actor_then_account_then_global_boundaries() {
    let database = TestDatabase::new();
    let store = SqliteStore::open_with_limits(
        database.path(),
        StorageLimits {
            sessions_per_actor: 1,
            sessions_per_account: 2,
            sessions_global: 3,
            ..StorageLimits::default()
        },
    )
    .await
    .unwrap();
    bootstrap_test_owner(&store).await;
    let local_member = activate_test_account_actor(
        database.path(),
        &TestAccountActor {
            account_id: "acc_local",
            user_id: "user-capacity-member",
            auth_session_id: "asi_capacity_member",
            token_byte: '2',
        },
    );
    let local_third = activate_test_account_actor(
        database.path(),
        &TestAccountActor {
            account_id: "acc_local",
            user_id: "user-capacity-third",
            auth_session_id: "asi_capacity_third",
            token_byte: '3',
        },
    );
    let second_account = activate_test_account_actor(
        database.path(),
        &TestAccountActor {
            account_id: "acc_capacity_two",
            user_id: "user-capacity-two",
            auth_session_id: "asi_capacity_two",
            token_byte: '4',
        },
    );
    let third_account = activate_test_account_actor(
        database.path(),
        &TestAccountActor {
            account_id: "acc_capacity_three",
            user_id: "user-capacity-three",
            auth_session_id: "asi_capacity_three",
            token_byte: '5',
        },
    );

    store
        .create_session_for_actor(
            &owner_authz(),
            CreateSessionRequest {
                id: "session-capacity-owner".into(),
                title: "Owner actor boundary".into(),
            },
            "session-capacity-owner",
        )
        .await
        .unwrap();
    assert!(matches!(
        store
            .create_session_for_actor(
                &owner_authz(),
                CreateSessionRequest {
                    id: "session-capacity-owner-plus-one".into(),
                    title: "Owner actor plus one".into(),
                },
                "session-capacity-owner-plus-one",
            )
            .await,
        Err(StorageError::StorageQuotaExceeded)
    ));
    store
        .create_session_for_actor(
            &local_member,
            CreateSessionRequest {
                id: "session-capacity-local-member".into(),
                title: "Local account boundary".into(),
            },
            "session-capacity-local-member",
        )
        .await
        .unwrap();
    assert!(matches!(
        store
            .create_session_for_actor(
                &local_third,
                CreateSessionRequest {
                    id: "session-capacity-local-plus-one".into(),
                    title: "Local account plus one".into(),
                },
                "session-capacity-local-plus-one",
            )
            .await,
        Err(StorageError::StorageQuotaExceeded)
    ));
    store
        .create_session_for_actor(
            &second_account,
            CreateSessionRequest {
                id: "session-capacity-second-account".into(),
                title: "Global exact boundary".into(),
            },
            "session-capacity-second-account",
        )
        .await
        .unwrap();
    assert!(matches!(
        store
            .create_session_for_actor(
                &third_account,
                CreateSessionRequest {
                    id: "session-capacity-global-plus-one".into(),
                    title: "Global plus one".into(),
                },
                "session-capacity-global-plus-one",
            )
            .await,
        Err(StorageError::StorageQuotaExceeded)
    ));

    let connection = rusqlite::Connection::open(database.path()).unwrap();
    let counts: (i64, i64, i64) = connection
        .query_row(
            r#"SELECT
                   (SELECT COUNT(*) FROM sessions
                    WHERE account_id = 'acc_local'
                      AND owner_user_id = 'user-owner'),
                   (SELECT COUNT(*) FROM sessions
                    WHERE account_id = 'acc_local'),
                   (SELECT COUNT(*) FROM sessions)"#,
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(counts, (1, 2, 3));
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
        sessions_per_actor: 3,
        sessions_per_account: 3,
        sessions_global: 3,
        open_turns_per_actor: 2,
        open_turns_per_account: 2,
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
                &owner_authz(),
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
                &owner_authz(),
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
        sessions_per_actor: 3,
        sessions_per_account: 3,
        sessions_global: 3,
        open_turns_per_actor: 3,
        open_turns_per_account: 3,
        open_turns_global: 3,
        active_reply_jobs_per_actor: 2,
        active_reply_jobs_per_account: 2,
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
                &owner_authz(),
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
                &owner_authz(),
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
            &owner_authz(),
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
            &owner_authz(),
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
            &owner_authz(),
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
    store
        .commit_review_for_actor(&owner_authz(), review.clone())
        .await
        .unwrap();
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
async fn distinct_dispatch_initiator_owns_capacity_and_finalization_reservation() {
    let database = TestDatabase::new();
    let store = SqliteStore::open_with_limits(
        database.path(),
        StorageLimits {
            active_dispatch_jobs_per_actor: 1,
            active_dispatch_jobs_per_account: 3,
            active_dispatch_jobs_global: 3,
            ..StorageLimits::default()
        },
    )
    .await
    .unwrap();
    let (snapshot, events) = seed_fixture();
    assert!(store.seed_if_empty(snapshot.clone(), events).await.unwrap());
    bootstrap_test_owner(&store).await;
    insert_test_member(database.path(), "user-member", "member");
    activate_test_member_auth(database.path(), "user-member", "asi_test_member");

    // Fill the approving owner's actor quota. A distinct initiating member
    // must still be admitted and charged to its own actor bucket.
    insert_active_dispatch_capacity_fixture(
        database.path(),
        "user-owner",
        "call-owner-capacity",
        "APR-OWNER-CAPACITY",
    );
    let mut review = approved_dispatch_commit(&snapshot, "distinct-dispatch-actors");
    review.dispatch.as_mut().unwrap().initiating_authz = Some(member_authz());
    assert_eq!(
        store
            .commit_review_for_actor(&owner_authz(), review)
            .await
            .unwrap(),
        CommitOutcome::Committed
    );

    let connection = rusqlite::Connection::open(database.path()).unwrap();
    let authority: (String, String, String) = connection
        .query_row(
            r#"SELECT job.initiating_actor_user_id,
                      job.approving_actor_user_id,
                      reservation.actor_user_id
               FROM dispatch_jobs job
               JOIN finalization_reservations reservation
                 ON reservation.kind = 'dispatch'
                AND reservation.run_id = job.run_id
                AND reservation.call_id = job.call_id
               WHERE job.call_id = 'call-local-001'"#,
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(
        authority,
        (
            "user-member".into(),
            "user-owner".into(),
            "user-member".into()
        )
    );
}

#[tokio::test]
async fn distinct_dispatch_rejects_when_the_initiator_actor_quota_is_full() {
    let database = TestDatabase::new();
    let store = SqliteStore::open_with_limits(
        database.path(),
        StorageLimits {
            active_dispatch_jobs_per_actor: 1,
            active_dispatch_jobs_per_account: 3,
            active_dispatch_jobs_global: 3,
            ..StorageLimits::default()
        },
    )
    .await
    .unwrap();
    let (snapshot, events) = seed_fixture();
    assert!(store.seed_if_empty(snapshot.clone(), events).await.unwrap());
    bootstrap_test_owner(&store).await;
    insert_test_member(database.path(), "user-member", "member");
    activate_test_member_auth(database.path(), "user-member", "asi_test_member");

    insert_active_dispatch_capacity_fixture(
        database.path(),
        "user-member",
        "call-member-capacity",
        "APR-MEMBER-CAPACITY",
    );
    let mut review = approved_dispatch_commit(&snapshot, "full-initiator-dispatch-capacity");
    review.dispatch.as_mut().unwrap().initiating_authz = Some(member_authz());
    assert!(matches!(
        store.commit_review_for_actor(&owner_authz(), review).await,
        Err(StorageError::DispatchQueueCapacityExceeded)
    ));
    assert!(
        store
            .dispatch_job("call-local-001")
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(store.load_run(RUN_ID).await.unwrap().events.len(), 6);
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
            auth_session_id: test_owner_auth_session_id(),
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
            authz: owner_authz_with_session("asi_capacity_1"),
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
                   id, token_hash, account_id, user_id, membership_revision,
                   csrf_hash, created_at, expires_at, last_seen_at
               ) VALUES (
                   'asi_expired_capacity', ?1, 'acc_local', 'user-owner', 1,
                   ?2, ?3, ?3, ?3
               )"#,
            params![expired_token, "2".repeat(64), FAR_PAST],
        )
        .unwrap();
    drop(connection);
    assert!(store.authenticate(&expired_token).await.unwrap().is_none());

    store
        .create_auth_session(AuthSessionCommit {
            authz: owner_authz_with_session("asi_capacity_2"),
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
                authz: owner_authz_with_session("asi_capacity_3"),
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
async fn stale_membership_sessions_are_revoked_and_do_not_block_new_revision_login() {
    const FAR_FUTURE: &str = "2999-01-01T00:00:00.000Z";

    let database = TestDatabase::new();
    let store = SqliteStore::open_with_limits(
        database.path(),
        StorageLimits {
            auth_sessions_per_user: 2,
            auth_sessions_global: 2,
            ..StorageLimits::default()
        },
    )
    .await
    .unwrap();
    store
        .replace_bootstrap_token(&"a".repeat(64), FAR_FUTURE)
        .await
        .unwrap();
    store
        .bootstrap_owner(BootstrapOwnerCommit {
            bootstrap_token_hash: "a".repeat(64),
            auth_session_id: test_owner_auth_session_id(),
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
            authz: owner_authz_with_session("asi_stale_capacity"),
            session_token_hash: "d".repeat(64),
            csrf_hash: "e".repeat(64),
            expires_at: FAR_FUTURE.into(),
        })
        .await
        .unwrap();
    assert_eq!(auth_session_count(database.path(), None), 2);

    bump_test_membership_revision(database.path(), "user-owner");
    assert!(store.authenticate(&"b".repeat(64)).await.unwrap().is_none());
    assert!(store.authenticate(&"d".repeat(64)).await.unwrap().is_none());
    let revised_authz = AuthzContext {
        account_id: AccountId::local(),
        user_id: "user-owner".into(),
        membership_role: MembershipRole::Member,
        membership_revision: MembershipRevision::new(2).unwrap(),
        auth_session_id: AuthSessionId::from_persistence("asi_current_capacity").unwrap(),
    };
    store
        .create_auth_session(AuthSessionCommit {
            authz: revised_authz.clone(),
            session_token_hash: "f".repeat(64),
            csrf_hash: "1".repeat(64),
            expires_at: FAR_FUTURE.into(),
        })
        .await
        .unwrap();
    assert_eq!(
        store
            .authenticate(&"f".repeat(64))
            .await
            .unwrap()
            .unwrap()
            .authz,
        revised_authz
    );
    let connection = rusqlite::Connection::open(database.path()).unwrap();
    let retained: (i64, i64) = connection
        .query_row(
            r#"SELECT COUNT(*), MIN(membership_revision)
               FROM auth_sessions WHERE user_id = 'user-owner'"#,
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(retained, (1, 2));
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
    assert_eq!(versions, (1_i64..=21).collect::<Vec<_>>());
    assert_eq!(
        connection
            .query_row(
                "SELECT used_bytes FROM event_payload_usage WHERE singleton = 1",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        expected_global_bytes,
        "reopening the migrated database must not charge historical payloads a second time"
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
            &owner_authz(),
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
            &owner_authz(),
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
            &owner_authz(),
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
    dispatch_store
        .commit_review_for_actor(&owner_authz(), review.clone())
        .await
        .unwrap();
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
        sessions_per_actor: 1,
        sessions_per_account: 1,
        sessions_global: 1,
        open_turns_per_actor: 1,
        open_turns_per_account: 1,
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
        sessions_per_actor: 1,
        sessions_per_account: 1,
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
                &owner_authz(),
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

fn insert_active_dispatch_capacity_fixture(
    path: &Path,
    initiating_actor_user_id: &str,
    call_id: &str,
    approval_id: &str,
) {
    let connection = rusqlite::Connection::open(path).unwrap();
    connection
        .pragma_update(None, "foreign_keys", true)
        .unwrap();
    connection
        .execute(
            r#"INSERT INTO dispatch_jobs(
                   call_id, account_id, run_id, approval_id,
                   approval_event_sequence, initiating_actor_user_id,
                   initiating_membership_revision, approving_actor_user_id,
                   approving_membership_revision, tool_name, tool_version,
                   effect, args_json, args_digest, policy_id, policy_revision,
                   sandbox_profile, status, attempt, result_json,
                   authorization_error_json, queued_at, started_at, finished_at,
                   start_event_sequence, result_event_sequence
               ) VALUES (
                   ?1, 'acc_local', ?2, ?3, 6, ?4, 1, 'user-owner', 1,
                   'local.capacity', '1.0.0', 'local_write', '{}', ?5,
                   'local-alpha', 'rev-capacity', 'workspace_write',
                   'queued', 0, NULL, NULL, ?6, NULL, NULL, NULL, NULL
               )"#,
            params![
                call_id,
                RUN_ID,
                approval_id,
                initiating_actor_user_id,
                format!("sha256:{}", "9".repeat(64)),
                "2026-08-27T00:00:00.000Z",
            ],
        )
        .unwrap();
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

fn bootstrap_token_hash(index: usize) -> String {
    format!("{index:064x}")
}

fn bootstrap_audit_rollup(path: &Path) -> (i64, String) {
    rusqlite::Connection::open(path)
        .unwrap()
        .query_row(
            r#"SELECT through_sequence, digest
               FROM bootstrap_audit_rollup WHERE singleton = 1"#,
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap()
}

fn bootstrap_audit_details(path: &Path) -> Vec<(i64, String, Option<String>, Option<String>)> {
    let connection = rusqlite::Connection::open(path).unwrap();
    let mut statement = connection
        .prepare(
            r#"SELECT sequence, token_hash, terminal_at, terminal_reason
               FROM bootstrap_tokens ORDER BY sequence"#,
        )
        .unwrap();
    statement
        .query_map([], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
        })
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap()
}

fn seed_v11_bootstrap_fixture(path: &Path, terminal_count: usize, live_expiry: &str) {
    let connection = rusqlite::Connection::open(path).unwrap();
    downgrade_bootstrap_audit_fixture_to_v11(&connection);
    for index in 1..=terminal_count {
        connection
            .execute(
                r#"INSERT INTO bootstrap_tokens(
                       token_hash, created_at, expires_at, used_at
                   ) VALUES (?1, '2026-08-26T00:00:00.000Z',
                             '2026-08-26T01:00:00.000Z',
                             '2026-08-26T00:30:00.000Z')"#,
                [bootstrap_token_hash(index)],
            )
            .unwrap();
    }
    connection
        .execute(
            r#"INSERT INTO bootstrap_tokens(
                   token_hash, created_at, expires_at, used_at
               ) VALUES (?1, '2026-08-26T00:59:00.000Z', ?2, NULL)"#,
            params![bootstrap_token_hash(terminal_count + 1), live_expiry],
        )
        .unwrap();
}

fn force_bootstrap_rollup_digest(path: &Path, digest: &str) {
    let connection = rusqlite::Connection::open(path).unwrap();
    let trigger_sql: String = connection
        .query_row(
            r#"SELECT sql FROM sqlite_schema
               WHERE type = 'trigger'
                 AND name = 'bootstrap_audit_rollup_enforce_update'"#,
            [],
            |row| row.get(0),
        )
        .unwrap();
    connection
        .execute_batch(
            "DROP TRIGGER bootstrap_audit_rollup_enforce_update; PRAGMA ignore_check_constraints = ON;",
        )
        .unwrap();
    connection
        .execute(
            "UPDATE bootstrap_audit_rollup SET digest = ?1 WHERE singleton = 1",
            [digest],
        )
        .unwrap();
    connection.execute_batch(&trigger_sql).unwrap();
}

fn downgrade_account_foundation_fixture_to_v12(connection: &rusqlite::Connection) {
    let mut version: i64 = connection
        .query_row("SELECT MAX(version) FROM schema_migrations", [], |row| {
            row.get(0)
        })
        .unwrap();
    if version < 13 {
        return;
    }
    if version >= 17 {
        drop_v17_fixture_objects(connection);
        version = 16;
    }
    if version >= 16 {
        drop_v16_fixture_objects(connection);
        version = 15;
    }
    if version >= 15 {
        drop_v15_fixture_objects(connection);
        version = 14;
    }
    if version >= 14 {
        downgrade_durable_authorization_fixture_to_v13(connection);
    }
    connection
        .execute_batch(
            r#"DROP TRIGGER accounts_reject_duplicate_insert;
               DROP TRIGGER accounts_reject_identity_update;
               DROP TRIGGER accounts_reject_delete;
               DROP TRIGGER account_memberships_reject_duplicate_insert;
               DROP TRIGGER account_memberships_enforce_revision;
               DROP TRIGGER account_memberships_preserve_last_active_owner;
               DROP TRIGGER account_memberships_reject_delete;
               DROP TRIGGER incidents_require_account_on_insert;
               DROP TRIGGER incidents_account_is_immutable;
               DROP TRIGGER sessions_require_account_on_insert;
               DROP TRIGGER sessions_account_is_immutable;
               DROP TRIGGER runs_require_account_on_insert;
               DROP TRIGGER runs_require_incident_account_on_update;
               DROP TRIGGER runs_account_is_immutable;
               DROP TRIGGER runtime_identity_require_account_on_insert;
               DROP TRIGGER session_runs_require_same_account;

               DROP INDEX incidents_account_id_idx;
               DROP INDEX sessions_account_id_idx;
               DROP INDEX sessions_account_updated_idx;
               DROP INDEX runs_account_id_idx;
               DROP INDEX runs_account_started_idx;
               DROP INDEX runs_account_incident_idx;
               DROP INDEX account_memberships_user_idx;
               DROP INDEX account_memberships_active_owner_idx;

               ALTER TABLE incidents DROP COLUMN account_id;
               ALTER TABLE sessions DROP COLUMN account_id;
               ALTER TABLE runs DROP COLUMN account_id;
               ALTER TABLE runtime_identity DROP COLUMN account_id;

               DROP TABLE account_memberships;
               DROP TABLE accounts;
               DELETE FROM schema_migrations WHERE version = 13;"#,
        )
        .unwrap();
}

fn downgrade_durable_authorization_fixture_to_v13(connection: &rusqlite::Connection) {
    let mut version: i64 = connection
        .query_row("SELECT MAX(version) FROM schema_migrations", [], |row| {
            row.get(0)
        })
        .unwrap();
    if version >= 17 {
        drop_v17_fixture_objects(connection);
        version = 16;
    }
    if version >= 16 {
        drop_v16_fixture_objects(connection);
        version = 15;
    }
    if version >= 15 {
        drop_v15_fixture_objects(connection);
    }
    let template = rusqlite::Connection::open_in_memory().unwrap();
    template
        .execute_batch(include_str!("../migrations/0001_init.sql"))
        .unwrap();
    template
        .execute_batch(include_str!("../migrations/0002_tool_execution.sql"))
        .unwrap();
    template
        .execute_batch(include_str!("../migrations/0003_runtime_identity.sql"))
        .unwrap();
    template
        .execute_batch(include_str!("../migrations/0004_sessions.sql"))
        .unwrap();
    template
        .execute_batch(include_str!("../migrations/0005_accounts.sql"))
        .unwrap();
    template
        .execute_batch(include_str!("../migrations/0006_actor_receipts.sql"))
        .unwrap();
    template
        .execute_batch(include_str!("../migrations/0007_reply_jobs.sql"))
        .unwrap();
    template
        .execute_batch(include_str!("../migrations/0008_actor_boundaries.sql"))
        .unwrap();
    template
        .execute_batch("DROP TRIGGER run_events_reject_update;")
        .unwrap();
    template
        .execute_batch(include_str!("../migrations/0009_point_queries.sql"))
        .unwrap();
    template
        .execute_batch(
            r#"CREATE INDEX run_events_approval_lookup_idx
                   ON run_events(run_id, approval_id, sequence DESC, approval_status)
                   WHERE approval_id IS NOT NULL;
               CREATE INDEX run_events_tool_call_lookup_idx
                   ON run_events(run_id, data_kind, call_id, sequence)
                   WHERE data_kind = 'tool_call_requested' AND call_id IS NOT NULL;
               CREATE INDEX run_events_policy_revision_idx
                   ON run_events(run_id, policy_revision)
                   WHERE policy_revision IS NOT NULL;
               CREATE INDEX session_runs_session_attached_idx
                   ON session_runs(session_id, attached_at, run_id);
               CREATE INDEX reply_jobs_started_idx
                   ON reply_jobs(status, started_at, id);
               CREATE INDEX dispatch_jobs_started_idx
                   ON dispatch_jobs(status, started_at, call_id);
               CREATE INDEX session_turns_open_recovery_idx
                   ON session_turns(status, session_id, ordinal, id);

               CREATE TRIGGER run_events_reject_update
               BEFORE UPDATE ON run_events
               BEGIN
                   SELECT RAISE(ABORT, 'run_events are append-only');
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
               END;"#,
        )
        .unwrap();
    template
        .execute_batch(include_str!("../migrations/0010_capacity.sql"))
        .unwrap();
    template
        .execute_batch(include_str!("../migrations/0011_event_payload_bytes.sql"))
        .unwrap();
    template
        .execute_batch(include_str!(
            "../migrations/0012_bootstrap_audit_retention.sql"
        ))
        .unwrap();
    template
        .execute_batch(include_str!(
            "../migrations/0013_account_membership_foundation.sql"
        ))
        .unwrap();

    let table_names = [
        "auth_sessions",
        "session_command_receipts",
        "idempotency_receipts",
        "reply_jobs",
        "dispatch_jobs",
        "finalization_reservations",
    ];
    let v13_tables = table_names
        .iter()
        .map(|name| {
            template
                .query_row(
                    "SELECT sql FROM sqlite_schema WHERE type = 'table' AND name = ?1",
                    [name],
                    |row| row.get::<_, String>(0),
                )
                .unwrap()
        })
        .collect::<Vec<_>>();
    let mut statement = template
        .prepare(
            r#"SELECT sql
               FROM sqlite_schema
               WHERE sql IS NOT NULL
                 AND (
                     (type IN ('index', 'trigger')
                      AND tbl_name IN (
                          'auth_sessions', 'session_command_receipts',
                          'idempotency_receipts', 'reply_jobs', 'dispatch_jobs',
                          'finalization_reservations'
                      ))
                     OR name IN (
                         'users_single_owner_idx',
                         'session_runs_require_same_owner'
                     )
                 )
               ORDER BY CASE type WHEN 'index' THEN 0 ELSE 1 END, name"#,
        )
        .unwrap();
    let v13_objects = statement
        .query_map([], |row| row.get::<_, String>(0))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();

    connection
        .execute_batch(
            "PRAGMA foreign_keys = OFF; PRAGMA legacy_alter_table = ON; BEGIN IMMEDIATE;",
        )
        .unwrap();

    let current_objects = {
        let mut statement = connection
            .prepare(
                r#"SELECT type, name
                   FROM sqlite_schema
                   WHERE sql IS NOT NULL
                     AND type IN ('index', 'trigger')
                     AND tbl_name IN (
                         'auth_sessions', 'session_command_receipts',
                         'idempotency_receipts', 'reply_jobs', 'dispatch_jobs',
                         'finalization_reservations'
                     )
                   ORDER BY CASE type WHEN 'trigger' THEN 0 ELSE 1 END, name"#,
            )
            .unwrap();
        statement
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap()
    };
    for (object_type, name) in current_objects {
        connection
            .execute_batch(&format!("DROP {object_type} \"{name}\";"))
            .unwrap();
    }

    connection
        .execute_batch(
            r#"ALTER TABLE finalization_reservations
                   RENAME TO finalization_reservations_v14;
               ALTER TABLE reply_jobs RENAME TO reply_jobs_v14;
               ALTER TABLE dispatch_jobs RENAME TO dispatch_jobs_v14;
               ALTER TABLE auth_sessions RENAME TO auth_sessions_v14;
               ALTER TABLE session_command_receipts
                   RENAME TO session_command_receipts_v14;
               ALTER TABLE idempotency_receipts
                   RENAME TO idempotency_receipts_v14;"#,
        )
        .unwrap();
    for table_sql in v13_tables {
        connection.execute_batch(&table_sql).unwrap();
    }
    connection
        .execute_batch(
            r#"INSERT INTO auth_sessions(
                   token_hash, user_id, csrf_hash, created_at, expires_at,
                   last_seen_at
               )
               SELECT token_hash, user_id, csrf_hash, created_at, expires_at,
                      last_seen_at
               FROM auth_sessions_v14;

               INSERT INTO session_command_receipts(
                   actor_scope, idempotency_key, operation,
                   request_fingerprint, response_json, session_id,
                   event_sequence, created_at
               )
               SELECT COALESCE(actor_user_id, '__legacy__'), idempotency_key,
                      operation, request_fingerprint, response_json, session_id,
                      event_sequence, created_at
               FROM session_command_receipts_v14;

               INSERT INTO idempotency_receipts(
                   actor_scope, idempotency_key, operation,
                   request_fingerprint, response_json, run_id,
                   event_sequence, created_at
               )
               SELECT COALESCE(actor_user_id, '__legacy__'), idempotency_key,
                      operation, request_fingerprint, response_json, run_id,
                      event_sequence, created_at
               FROM idempotency_receipts_v14;

               INSERT INTO reply_jobs(
                   id, actor_user_id, session_id, turn_id, provider_name,
                   model_name, status, attempt, request_json, response_json,
                   error_json, completion_fingerprint,
                   assistant_event_sequence, terminal_event_sequence,
                   queued_at, started_at, finished_at
               )
               SELECT id, actor_user_id, session_id, turn_id, provider_name,
                      model_name, status, attempt, request_json, response_json,
                      error_json, completion_fingerprint,
                      assistant_event_sequence, terminal_event_sequence,
                      queued_at, started_at, finished_at
               FROM reply_jobs_v14;

               INSERT INTO dispatch_jobs(
                   call_id, run_id, approval_id, approval_event_sequence,
                   approving_actor_user_id, tool_name, tool_version, effect,
                   args_json, args_digest, policy_id, policy_revision,
                   sandbox_profile, status, attempt, result_json,
                   authorization_error_json, queued_at, started_at,
                   finished_at, start_event_sequence, result_event_sequence
               )
               SELECT call_id, run_id, approval_id, approval_event_sequence,
                      approving_actor_user_id, tool_name, tool_version, effect,
                      args_json, args_digest, policy_id, policy_revision,
                      sandbox_profile, status, attempt, result_json,
                      authorization_error_json, queued_at, started_at,
                      finished_at, start_event_sequence, result_event_sequence
               FROM dispatch_jobs_v14;

               INSERT INTO finalization_reservations(
                   kind, scope_id, session_id, turn_id, run_id, call_id,
                   remaining_event_slots, reserved_bytes, created_at,
                   remaining_event_payload_bytes
               )
               SELECT kind, COALESCE(actor_user_id, '__legacy__'), session_id,
                      turn_id, run_id, call_id, remaining_event_slots,
                      reserved_bytes, created_at,
                      remaining_event_payload_bytes
               FROM finalization_reservations_v14;

               DROP TABLE finalization_reservations_v14;
               DROP TABLE reply_jobs_v14;
               DROP TABLE dispatch_jobs_v14;
               DROP TABLE auth_sessions_v14;
               DROP TABLE session_command_receipts_v14;
               DROP TABLE idempotency_receipts_v14;"#,
        )
        .unwrap();
    for object_sql in v13_objects {
        connection.execute_batch(&object_sql).unwrap();
    }
    connection
        .execute_batch(
            r#"DELETE FROM schema_migrations WHERE version = 14;
               COMMIT;
               PRAGMA legacy_alter_table = OFF;
               PRAGMA foreign_keys = ON;"#,
        )
        .unwrap();
}

fn drop_v15_fixture_objects(connection: &rusqlite::Connection) {
    connection
        .execute_batch(
            r#"DROP TABLE account_audit_events;
               DROP TABLE account_audit_archive_state;
               DROP TABLE account_audit_policies;
               DROP TABLE account_audit_rollups;
               DROP TABLE member_setup_tokens;
               DELETE FROM schema_migrations WHERE version = 15;"#,
        )
        .unwrap();
}

fn drop_v16_fixture_objects(connection: &rusqlite::Connection) {
    connection
        .execute_batch(
            r#"DROP INDEX session_events_reply_context_idx;
               DELETE FROM schema_migrations WHERE version = 16;"#,
        )
        .unwrap();
}

fn drop_v17_fixture_objects(connection: &rusqlite::Connection) {
    let version: i64 = connection
        .query_row("SELECT MAX(version) FROM schema_migrations", [], |row| {
            row.get(0)
        })
        .unwrap();
    if version >= 20 {
        drop_v20_fixture_objects(connection);
    }
    if version >= 19 {
        downgrade_agent_deployment_manifest_fixture_to_v18(connection);
    }
    connection
        .execute_batch(
            r#"DROP INDEX session_events_turn_kind_idx;
               DROP TABLE agent_review_receipts;
               DROP TABLE agent_tool_calls;
               DROP TABLE agent_model_jobs;
               DROP TABLE agent_turns;
               DELETE FROM schema_migrations WHERE version >= 17;"#,
        )
        .unwrap();
}

fn downgrade_member_lifecycle_fixture_to_v14(connection: &rusqlite::Connection) {
    downgrade_durable_authorization_fixture_to_v13(connection);
    connection.execute_batch("BEGIN IMMEDIATE;").unwrap();
    connection
        .execute_batch(include_str!(
            "../migrations/0014_account_scoped_durable_authorization.sql"
        ))
        .unwrap();
    connection
        .execute(
            r#"INSERT INTO schema_migrations(version, applied_at)
               VALUES (14, '2026-08-27T00:00:00.000Z')"#,
            [],
        )
        .unwrap();
    connection.execute_batch("COMMIT;").unwrap();
}

fn downgrade_bootstrap_audit_fixture_to_v11(connection: &rusqlite::Connection) {
    downgrade_account_foundation_fixture_to_v12(connection);
    connection
        .execute_batch(
            r#"DROP TRIGGER bootstrap_tokens_require_next_sequence;
               DROP TRIGGER bootstrap_tokens_enforce_terminal_transition;
               DROP TRIGGER bootstrap_tokens_reject_uncommitted_delete;
               DROP TRIGGER bootstrap_audit_rollup_enforce_update;
               DROP TRIGGER bootstrap_audit_rollup_reject_delete;
               DROP INDEX bootstrap_tokens_one_live_idx;
               DROP INDEX bootstrap_tokens_terminal_sequence_idx;

               ALTER TABLE bootstrap_tokens RENAME TO bootstrap_tokens_v12;

               CREATE TABLE bootstrap_tokens (
                   token_hash TEXT PRIMARY KEY CHECK (length(token_hash) = 64),
                   created_at TEXT NOT NULL,
                   expires_at TEXT NOT NULL,
                   used_at    TEXT
               ) STRICT;

               INSERT INTO bootstrap_tokens(token_hash, created_at, expires_at, used_at)
               SELECT token_hash, created_at, expires_at, terminal_at
               FROM bootstrap_tokens_v12
               ORDER BY sequence;

               DROP TABLE bootstrap_tokens_v12;
               DROP TABLE bootstrap_audit_rollup;

               CREATE UNIQUE INDEX bootstrap_tokens_one_live_idx
                   ON bootstrap_tokens((1)) WHERE used_at IS NULL;

               CREATE TRIGGER bootstrap_tokens_enforce_single_use
               BEFORE UPDATE ON bootstrap_tokens
               WHEN NOT (
                   OLD.used_at IS NULL
                   AND NEW.used_at IS NOT NULL
                   AND NEW.token_hash = OLD.token_hash
                   AND NEW.created_at = OLD.created_at
                   AND NEW.expires_at = OLD.expires_at
               )
               BEGIN
                   SELECT RAISE(ABORT, 'bootstrap token can only transition to used');
               END;

               CREATE TRIGGER bootstrap_tokens_reject_delete
               BEFORE DELETE ON bootstrap_tokens
               BEGIN
                   SELECT RAISE(ABORT, 'bootstrap tokens are security audit records');
               END;

               DELETE FROM schema_migrations WHERE version = 12;"#,
        )
        .unwrap();
}

fn downgrade_capacity_fixture_to_v9(path: &Path) {
    let connection = rusqlite::Connection::open(path).unwrap();
    downgrade_bootstrap_audit_fixture_to_v11(&connection);
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
    downgrade_bootstrap_audit_fixture_to_v11(&connection);
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
        .bind_runtime_identity(test_agent_runtime_identity())
        .await
        .unwrap();
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
            auth_session_id: test_owner_auth_session_id(),
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

fn member_setup_token_pair() -> (MemberSetupToken, String) {
    let token = MemberSetupToken::generate().unwrap();
    let presented = token.expose_secret().to_owned();
    (token, presented)
}

fn member_setup_commit(
    presented: &str,
    auth_session_id: &str,
    hash_nibble: &str,
) -> MemberSetupCommit {
    MemberSetupCommit {
        setup_token: MemberSetupToken::from_presented(presented).unwrap(),
        password_hash: "$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$ZGlnaWVzdA".into(),
        auth_session_id: AuthSessionId::from_persistence(auth_session_id).unwrap(),
        session_token_hash: hash_nibble.repeat(64),
        csrf_hash: "8".repeat(64),
        session_expires_at: "2999-01-01T00:00:00.000Z".into(),
    }
}

async fn provision_test_member_for_reply(store: &SqliteStore) -> AuthzContext {
    let (token, presented) = member_setup_token_pair();
    store
        .create_member(
            &owner_authz(),
            CreateMemberCommit {
                user_id: "user-member".into(),
                username: "member".into(),
                setup_token: token,
            },
        )
        .await
        .unwrap();
    store
        .complete_member_setup(member_setup_commit(&presented, "asi_test_member", "e"))
        .await
        .unwrap()
        .principal
        .authz
}

fn insert_secondary_test_account(path: &Path) -> AuthzContext {
    let connection = rusqlite::Connection::open(path).unwrap();
    connection
        .pragma_update(None, "foreign_keys", true)
        .unwrap();
    connection
        .execute_batch(
            r#"INSERT INTO accounts(id, name, status, created_at, updated_at)
               VALUES (
                   'acc_secondary', 'Secondary', 'active',
                   '2026-08-27T00:00:00.000Z', '2026-08-27T00:00:00.000Z'
               );
               INSERT INTO users(
                   id, username, role, status, password_hash, created_at, updated_at
               ) VALUES (
                   'user-secondary-owner', 'secondary-owner', 'owner', 'active',
                   '$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$ZGlnaWVzdA',
                   '2026-08-27T00:00:00.000Z', '2026-08-27T00:00:00.000Z'
               );
               INSERT INTO account_memberships(
                   account_id, user_id, role, status, revision, created_at, updated_at
               ) VALUES (
                   'acc_secondary', 'user-secondary-owner', 'owner', 'active', 1,
                   '2026-08-27T00:00:00.000Z', '2026-08-27T00:00:00.000Z'
               );
               INSERT INTO user_preferences(
                   user_id, theme, preferred_model, revision, updated_at
               ) VALUES (
                   'user-secondary-owner', 'system', NULL, 1,
                   '2026-08-27T00:00:00.000Z'
               );
               INSERT INTO auth_sessions(
                   id, token_hash, account_id, user_id, membership_revision,
                   csrf_hash, created_at, expires_at, last_seen_at
               ) VALUES (
                   'asi_secondary_owner',
                   '9999999999999999999999999999999999999999999999999999999999999999',
                   'acc_secondary', 'user-secondary-owner', 1,
                   '8888888888888888888888888888888888888888888888888888888888888888',
                   '2026-08-27T00:00:00.000Z', '2999-01-01T00:00:00.000Z',
                   '2026-08-27T00:00:00.000Z'
               );
               INSERT INTO account_audit_rollups(
                   account_id, through_sequence, event_count, digest,
                   last_event_hash, updated_at
               ) VALUES (
                   'acc_secondary', 0, 0,
                   '0000000000000000000000000000000000000000000000000000000000000000',
                   '0000000000000000000000000000000000000000000000000000000000000000',
                   '2026-08-27T00:00:00.000Z'
               );
               INSERT INTO account_audit_policies(
                   account_id, detail_rows, legal_hold, archive_required,
                   revision, updated_at
               ) VALUES (
                   'acc_secondary', 2, 0, 0, 1, '2026-08-27T00:00:00.000Z'
               );
               INSERT INTO account_audit_archive_state(
                   account_id, through_sequence, event_hash, archive_reference,
                   revision, updated_at
               ) VALUES (
                   'acc_secondary', 0,
                   '0000000000000000000000000000000000000000000000000000000000000000',
                   NULL, 1, '2026-08-27T00:00:00.000Z'
               );"#,
        )
        .unwrap();
    AuthzContext {
        account_id: AccountId::from_persistence("acc_secondary").unwrap(),
        user_id: "user-secondary-owner".into(),
        membership_role: MembershipRole::Owner,
        membership_revision: MembershipRevision::new(1).unwrap(),
        auth_session_id: AuthSessionId::from_persistence("asi_secondary_owner").unwrap(),
    }
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

fn bump_test_membership_revision(path: &Path, user_id: &str) {
    let connection = rusqlite::Connection::open(path).unwrap();
    connection
        .execute(
            r#"INSERT INTO users(
                   id, username, role, status, password_hash, created_at, updated_at
               ) VALUES (
                   'user-backup-owner', 'backup-owner', 'owner', 'active', ?1, ?2, ?2
               )"#,
            params![
                "$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$ZGlnaWVzdA",
                "2026-08-27T00:00:00.000Z"
            ],
        )
        .unwrap();
    connection
        .execute(
            r#"INSERT INTO account_memberships(
                   account_id, user_id, role, status, revision, created_at, updated_at
               ) VALUES (
                   'acc_local', 'user-backup-owner', 'owner', 'active', 1, ?1, ?1
               )"#,
            ["2026-08-27T00:00:00.000Z"],
        )
        .unwrap();
    connection
        .execute(
            r#"UPDATE account_memberships
               SET role = 'member', revision = revision + 1,
                   updated_at = '9999-12-31T23:59:59.999Z'
               WHERE account_id = 'acc_local' AND user_id = ?1"#,
            [user_id],
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

fn activate_test_member_auth(path: &Path, user_id: &str, auth_session_id: &str) {
    let connection = rusqlite::Connection::open(path).unwrap();
    connection
        .pragma_update(None, "foreign_keys", true)
        .unwrap();
    connection
        .execute(
            r#"INSERT INTO account_memberships(
                   account_id, user_id, role, status, revision, created_at, updated_at
               ) VALUES (
                   'acc_local', ?1, 'member', 'active', 1,
                   '2026-08-27T00:00:00.000Z', '2026-08-27T00:00:00.000Z'
               )"#,
            [user_id],
        )
        .unwrap();
    let token_hash = if user_id == "foreign-user" {
        "f".repeat(64)
    } else {
        "e".repeat(64)
    };
    connection
        .execute(
            r#"INSERT INTO auth_sessions(
                   id, token_hash, account_id, user_id, membership_revision,
                   csrf_hash, created_at, expires_at, last_seen_at
               ) VALUES (
                   ?1, ?2, 'acc_local', ?3, 1, ?4,
                   '2026-08-27T00:00:00.000Z', '2999-01-01T00:00:00.000Z',
                   '2026-08-27T00:00:00.000Z'
               )"#,
            params![auth_session_id, token_hash, user_id, "d".repeat(64)],
        )
        .unwrap();
}

struct TestAccountActor<'a> {
    account_id: &'a str,
    user_id: &'a str,
    auth_session_id: &'a str,
    token_byte: char,
}

fn activate_test_account_actor(path: &Path, actor: &TestAccountActor<'_>) -> AuthzContext {
    let connection = rusqlite::Connection::open(path).unwrap();
    connection
        .pragma_update(None, "foreign_keys", true)
        .unwrap();
    if actor.account_id != "acc_local" {
        connection
            .execute(
                r#"INSERT INTO accounts(id, name, status, created_at, updated_at)
                   VALUES (?1, ?1, 'active', ?2, ?2)"#,
                params![actor.account_id, "2026-08-27T00:00:00.000Z"],
            )
            .unwrap();
    }
    connection
        .execute(
            r#"INSERT INTO users(
                   id, username, role, status, password_hash, created_at, updated_at
               ) VALUES (?1, ?1, 'member', 'active', ?2, ?3, ?3)"#,
            params![
                actor.user_id,
                "$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$ZGlnaWVzdA",
                "2026-08-27T00:00:00.000Z",
            ],
        )
        .unwrap();
    connection
        .execute(
            r#"INSERT INTO account_memberships(
                   account_id, user_id, role, status, revision, created_at, updated_at
               ) VALUES (?1, ?2, 'member', 'active', 1, ?3, ?3)"#,
            params![actor.account_id, actor.user_id, "2026-08-27T00:00:00.000Z"],
        )
        .unwrap();
    connection
        .execute(
            r#"INSERT INTO auth_sessions(
                   id, token_hash, account_id, user_id, membership_revision,
                   csrf_hash, created_at, expires_at, last_seen_at
               ) VALUES (?1, ?2, ?3, ?4, 1, ?5, ?6, ?7, ?6)"#,
            params![
                actor.auth_session_id,
                actor.token_byte.to_string().repeat(64),
                actor.account_id,
                actor.user_id,
                "a".repeat(64),
                "2026-08-27T00:00:00.000Z",
                "2999-01-01T00:00:00.000Z",
            ],
        )
        .unwrap();
    AuthzContext {
        account_id: AccountId::from_persistence(actor.account_id).unwrap(),
        user_id: actor.user_id.into(),
        membership_role: MembershipRole::Member,
        membership_revision: MembershipRevision::new(1).unwrap(),
        auth_session_id: AuthSessionId::from_persistence(actor.auth_session_id).unwrap(),
    }
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
                   projection_sequence, active_turn_id, owner_user_id, account_id
               ) VALUES (
                   ?1, ?2, 'ready', ?3, ?3, 0, 0, NULL, 'user-owner', 'acc_local'
               )"#,
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
                   kind, account_id, actor_user_id, session_id, turn_id, run_id, call_id,
                   remaining_event_slots, remaining_event_payload_bytes,
                   reserved_bytes, created_at
               ) VALUES (
                   'session_turn', 'acc_local', 'user-owner', ?1, ?2, NULL, NULL,
                   2, ?3, NULL, ?4
               )"#,
            params![session_id, turn_id, finalization_payload_bytes, timestamp],
        )
        .unwrap();
    connection
        .execute(
            r#"INSERT INTO reply_jobs(
                   id, account_id, actor_user_id, actor_membership_revision,
                   session_id, turn_id, provider_name, model_name,
                   status, attempt, request_json, response_json, error_json,
                   completion_fingerprint, assistant_event_sequence,
                   terminal_event_sequence, queued_at, started_at, finished_at
               ) VALUES (
                   ?1, 'acc_local', 'user-owner', 1, ?2, ?3, 'test-provider', 'test-model',
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
        .bind_runtime_identity(test_agent_runtime_identity())
        .await
        .unwrap();
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
        authz: owner_authz(),
        provider_name: "test-provider".into(),
        model_name: Some("test-model".into()),
        request_json: json!({
            "messages": [{"role": "user", "content": format!("reply to {turn_id}")}]
        }),
    }
}

fn agent_turn_spec(id: &str, turn_id: &str) -> AgentTurnSpec {
    let manifest = test_agent_manifest();
    agent_turn_spec_with_manifest(id, turn_id, manifest)
}

fn agent_turn_spec_with_manifest(
    id: &str,
    turn_id: &str,
    manifest: ManifestEnvelope,
) -> AgentTurnSpec {
    AgentTurnSpec {
        id: id.into(),
        authz: owner_authz(),
        manifest: manifest.clone(),
        environment: "local".into(),
        provider_name: "test-provider".into(),
        model_name: Some("test-model".into()),
        request_json: agent_request_with_tools(
            json!({
                "messages": [{
                    "role": "user",
                    "content": format!("reply to {turn_id}"),
                }],
            }),
            &manifest,
        ),
    }
}

fn test_agent_runtime_identity() -> RuntimeIdentity {
    RuntimeIdentity {
        profile: "local-development".into(),
        environment: "local".into(),
        primary_session_id: "session-alpha".into(),
        primary_run_id: "run-agent-tests".into(),
        policy_id: "local".into(),
        policy_revision: "local/v1".into(),
    }
}

fn test_agent_manifest() -> ManifestEnvelope {
    let provider = ManifestProvider::new(
        "test-provider",
        Some("test-model".into()),
        AssistantReplyKind::Model,
    )
    .unwrap();
    let policy = ManifestPolicy::new("local", "local/v1").unwrap();
    let tool = ManifestTool::new(
        "workspace_list",
        "1.0.0",
        "List bounded workspace entries.",
        json!({
            "type": "object",
            "properties": {
                "path": {"type": "string"},
                "depth": {"type": "integer"},
            },
            "required": ["path", "depth"],
            "additionalProperties": false,
        }),
        ToolEffect::ReadOnly,
        SandboxProfile::ReadOnly,
        ToolExecutorStatus::Available,
    )
    .unwrap();
    let spec = AgentSpec::new(
        "zeus-storage-test-agent",
        "1",
        "local-development",
        "local",
        provider,
        policy,
    )
    .unwrap()
    .with_tools(vec![tool])
    .unwrap();
    ManifestEnvelope::from_deployment(
        AgentDeployment::new("zeus-storage-test-deployment", "1", spec).unwrap(),
    )
    .unwrap()
}

fn mutate_test_agent_manifest(mutate: impl FnOnce(&mut deployment::AgentSpec)) -> ManifestEnvelope {
    let mut manifest = test_agent_manifest().manifest;
    mutate(&mut manifest.deployment.spec);
    ManifestEnvelope::new(manifest).unwrap()
}

fn prompt_bound_test_agent_manifest(prompt_content: &str) -> ManifestEnvelope {
    mutate_test_agent_manifest(|spec| {
        spec.prompt = Some(
            ManifestPromptBinding::from_content(
                "zeus-storage-test-system-prompt",
                "1",
                prompt_content,
            )
            .unwrap(),
        );
    })
}

fn legacy_dotted_test_agent_manifest() -> ManifestEnvelope {
    mutate_test_agent_manifest(|spec| {
        spec.tools[0].name = "workspace.list".into();
    })
}

fn rewrite_agent_as_v19_promptless_legacy(
    connection: &rusqlite::Connection,
    agent_id: &str,
    system_prompt: &str,
) -> ManifestEnvelope {
    let dotted_manifest = legacy_dotted_test_agent_manifest();
    downgrade_agent_deployment_manifest_fixture_to_v18(connection);
    connection
        .execute_batch(include_str!(
            "../migrations/0019_agent_deployment_manifest.sql"
        ))
        .unwrap();
    connection
        .execute(
            "INSERT INTO schema_migrations(version, applied_at) VALUES (19, ?1)",
            ["2026-08-27T00:00:19.000Z"],
        )
        .unwrap();
    connection
        .execute(
            r#"INSERT INTO agent_deployment_manifests(
                   digest, schema_version, envelope_json, created_at
               ) VALUES (?1, ?2, ?3, ?4)"#,
            params![
                dotted_manifest.digest,
                i64::from(dotted_manifest.schema_version),
                String::from_utf8(dotted_manifest.canonical_json_bytes().unwrap()).unwrap(),
                "2026-08-27T00:00:19.000Z",
            ],
        )
        .unwrap();

    let agent_identity = stored_trigger_sql(connection, "agent_turns_reject_identity_update");
    let agent_forward = stored_trigger_sql(connection, "agent_turns_enforce_forward_revision");
    connection
        .execute_batch(
            r#"DROP TRIGGER agent_turns_reject_identity_update;
               DROP TRIGGER agent_turns_enforce_forward_revision;"#,
        )
        .unwrap();
    connection
        .execute(
            r#"UPDATE agent_turns SET deployment_manifest_digest = ?1 WHERE id = ?2"#,
            params![dotted_manifest.digest, agent_id],
        )
        .unwrap();
    connection.execute_batch(&agent_identity).unwrap();
    connection.execute_batch(&agent_forward).unwrap();

    let model_input = stored_trigger_sql(connection, "agent_model_jobs_reject_input_update");
    let model_forward =
        stored_trigger_sql(connection, "agent_model_jobs_enforce_forward_transition");
    let stored_request: String = connection
        .query_row(
            "SELECT request_json FROM agent_model_jobs WHERE agent_id = ?1 AND step = 1",
            [agent_id],
            |row| row.get(0),
        )
        .unwrap();
    let mut dotted_request = serde_json::from_str::<Value>(&stored_request).unwrap();
    dotted_request["tools"][0]["name"] = json!("workspace.list");
    dotted_request["messages"].as_array_mut().unwrap().insert(
        0,
        json!({
            "role": "system",
            "content": system_prompt,
        }),
    );
    connection
        .execute_batch(
            r#"DROP TRIGGER agent_model_jobs_reject_input_update;
               DROP TRIGGER agent_model_jobs_enforce_forward_transition;"#,
        )
        .unwrap();
    connection
        .execute(
            "UPDATE agent_model_jobs SET request_json = ?1 WHERE agent_id = ?2 AND step = 1",
            params![serde_json::to_string(&dotted_request).unwrap(), agent_id],
        )
        .unwrap();
    connection.execute_batch(&model_input).unwrap();
    connection.execute_batch(&model_forward).unwrap();
    assert_eq!(
        connection
            .query_row("SELECT MAX(version) FROM schema_migrations", [], |row| {
                row.get::<_, i64>(0)
            })
            .unwrap(),
        19
    );
    dotted_manifest
}

fn agent_turn_spec_with_system_prompt(
    id: &str,
    turn_id: &str,
    manifest: ManifestEnvelope,
    prompt_content: &str,
) -> AgentTurnSpec {
    let mut spec = agent_turn_spec_with_manifest(id, turn_id, manifest);
    spec.request_json["messages"]
        .as_array_mut()
        .unwrap()
        .insert(
            0,
            json!({
                "role": "system",
                "content": prompt_content,
            }),
        );
    spec
}

fn agent_request_with_tools(mut request: Value, manifest: &ManifestEnvelope) -> Value {
    let tools = manifest
        .manifest
        .deployment
        .spec
        .tools
        .iter()
        .map(|tool| {
            json!({
                "name": tool.name,
                "description": tool.description,
                "parameters": tool.input_schema,
            })
        })
        .collect::<Vec<_>>();
    request
        .as_object_mut()
        .expect("Agent test request is an object")
        .insert("tools".into(), Value::Array(tools));
    request
}

fn test_agent_request(mut request: Value) -> Value {
    // Storage-focused fixtures often specify only the continuation result.
    // Complete that shorthand into the same valid provider transcript the API
    // persists, so tests exercise their intended durable invariant without
    // bypassing the typed request contract.
    let messages = request
        .get_mut("messages")
        .and_then(Value::as_array_mut)
        .expect("Agent test request contains a messages array");
    if let Some(tool_index) = messages
        .iter()
        .rposition(|message| message.get("role") == Some(&json!("tool")))
    {
        let tool_call_id = messages[tool_index]["tool_call_id"]
            .as_str()
            .expect("Agent test tool result has a call ID")
            .to_owned();
        let has_matching_call = tool_index.checked_sub(1).is_some_and(|assistant_index| {
            messages[assistant_index].get("role") == Some(&json!("assistant"))
                && messages[assistant_index]["tool_call"]["id"] == tool_call_id
        });
        if !has_matching_call {
            let mut tool_index = tool_index;
            if tool_index == 0 {
                messages.insert(
                    0,
                    json!({
                        "role": "user",
                        "content": "Exercise the durable Agent continuation",
                    }),
                );
                tool_index += 1;
            }
            messages.insert(
                tool_index,
                json!({
                    "role": "assistant",
                    "content": "",
                    "tool_call": {
                        "id": tool_call_id,
                        "name": "workspace_list",
                        "arguments": {"path": ".", "depth": 2},
                    },
                }),
            );
        }
    }
    agent_request_with_tools(request, &test_agent_manifest())
}

fn contains_forbidden_manifest_key(value: &Value) -> bool {
    match value {
        Value::Object(object) => object.iter().any(|(key, value)| {
            let key = key.to_ascii_lowercase();
            key.contains("endpoint")
                || key.contains("api_key")
                || key.contains("secret")
                || contains_forbidden_manifest_key(value)
        }),
        Value::Array(values) => values.iter().any(contains_forbidden_manifest_key),
        _ => false,
    }
}

fn agent_model_provenance() -> AssistantReplyProvenance {
    AssistantReplyProvenance {
        provider_id: "test-provider".into(),
        model: Some("test-model".into()),
        reply_kind: AssistantReplyKind::Model,
    }
}

fn agent_final_response_json(content: &str) -> Value {
    json!({
        "output": {
            "type": "final",
            "content": content,
        },
        "finish_reason": "stop",
        "provider": {
            "provider_id": "test-provider",
            "model": "test-model",
            "reply_kind": "model",
        },
    })
}

fn agent_tool_call_spec(call_id: &str, policy_decision: PolicyDecision) -> AgentToolCallSpec {
    let arguments_json = json!({"path": ".", "depth": 2});
    AgentToolCallSpec {
        call_id: call_id.into(),
        provider_call_id: format!("provider-call-{call_id}"),
        tool_name: "workspace_list".into(),
        tool_version: "1.0.0".into(),
        arguments_digest: tools::arguments_digest(&arguments_json),
        arguments_json,
        effect: ToolEffect::ReadOnly,
        sandbox_profile: SandboxProfile::ReadOnly,
        executor_status: ToolExecutorStatus::Available,
        policy_decision,
        policy_revision: "local/v1".into(),
    }
}

fn agent_tool_response_json(call: &AgentToolCallSpec) -> Value {
    json!({
        "output": {
            "type": "tool_call",
            "call": {
                "id": call.provider_call_id,
                "name": call.tool_name,
                "arguments": call.arguments_json,
            },
        },
        "finish_reason": "tool_calls",
        "provider": {
            "provider_id": "test-provider",
            "model": "test-model",
            "reply_kind": "model",
        },
    })
}

#[derive(Clone, Copy, Debug)]
enum V17AgentToolPath {
    Completed,
    PolicyDenied,
    ApprovalRejected,
    Queued,
    Started,
    LegacyTerminal,
}

impl V17AgentToolPath {
    fn label(self) -> &'static str {
        match self {
            Self::Completed => "completed",
            Self::PolicyDenied => "policy-denied",
            Self::ApprovalRejected => "approval-rejected",
            Self::Queued => "queued",
            Self::Started => "started",
            Self::LegacyTerminal => "legacy-terminal",
        }
    }
}

struct V17AgentToolPathFixture {
    database: TestDatabase,
    call_id: String,
    turn_id: String,
    tool_replay: AgentToolCompletionCommit,
    model_replay: Option<AgentModelSuccessCommit>,
    review_replay: Option<AgentReviewCommit>,
}

async fn v17_agent_tool_path_fixture(path: V17AgentToolPath) -> V17AgentToolPathFixture {
    let database = TestDatabase::new();
    let store = created_owned_file_session_store(database.path()).await;
    let label = path.label();
    let turn_id = format!("turn-agent-v17-{label}");
    store
        .start_turn_and_enqueue_agent_for_actor(
            &owner_authz(),
            "session-alpha",
            StartTurnRequest {
                turn_id: turn_id.clone(),
                user_message: format!("Exercise the v17 {label} migration path"),
                expected_sequence: 1,
            },
            &format!("agent-v17-{label}-start"),
            agent_turn_spec(&format!("agent-v17-{label}"), &turn_id),
        )
        .await
        .unwrap();
    let AgentModelClaimOutcome::Claimed(job) = store
        .claim_next_agent_model(&test_agent_manifest())
        .await
        .unwrap()
    else {
        panic!("the {label} model job must be claimable");
    };
    let policy = match path {
        V17AgentToolPath::PolicyDenied => PolicyDecision::Deny,
        V17AgentToolPath::ApprovalRejected => PolicyDecision::RequireApproval,
        V17AgentToolPath::Completed
        | V17AgentToolPath::Queued
        | V17AgentToolPath::Started
        | V17AgentToolPath::LegacyTerminal => PolicyDecision::Allow,
    };
    let call = agent_tool_call_spec(&format!("agent-call-v17-{label}"), policy);
    let next_request_json = test_agent_request(json!({
        "messages": [{
            "role": "tool",
            "content": format!("v17 {label} continuation"),
            "tool_call_id": call.provider_call_id,
        }],
    }));
    let mut model_replay = None;
    let mut review_replay = None;
    let tool_replay = match path {
        V17AgentToolPath::PolicyDenied => {
            let result_json = json!({
                "code": "policy_denied",
                "message": "the call is denied by local policy",
            });
            let commit = AgentModelSuccessCommit {
                job_id: job.id,
                response_json: agent_tool_response_json(&call),
                resolution: AgentModelResolution::PolicyDenied {
                    call: call.clone(),
                    result_json: result_json.clone(),
                    next_request_json: Some(next_request_json.clone()),
                },
            };
            let completion = store
                .complete_agent_model_success(commit.clone())
                .await
                .unwrap();
            assert!(matches!(completion, AgentModelCompletion::ToolCall { .. }));
            model_replay = Some(commit);
            AgentToolCompletionCommit {
                call_id: call.call_id.clone(),
                status: AgentToolCallStatus::NotDispatched,
                result_json,
                provider_request_id: None,
                next_request_json: Some(next_request_json.clone()),
            }
        }
        V17AgentToolPath::ApprovalRejected => {
            store
                .complete_agent_model_success(AgentModelSuccessCommit {
                    job_id: job.id,
                    response_json: agent_tool_response_json(&call),
                    resolution: AgentModelResolution::ToolCall { call: call.clone() },
                })
                .await
                .unwrap();
            let review = AgentReviewCommit {
                call_id: call.call_id.clone(),
                decision: ReviewDecision::Reject,
                note: Some("migration rejection".into()),
                idempotency_key: "agent-v17-approval-rejected".into(),
                next_request_json: Some(next_request_json.clone()),
            };
            store
                .review_agent_tool_for_actor(
                    &owner_authz(),
                    "session-alpha",
                    &turn_id,
                    review.clone(),
                )
                .await
                .unwrap();
            let result_json =
                protocol::agent_approval_rejected_result(&call.call_id, review.note.as_deref());
            review_replay = Some(review);
            AgentToolCompletionCommit {
                call_id: call.call_id.clone(),
                status: AgentToolCallStatus::NotDispatched,
                result_json,
                provider_request_id: None,
                next_request_json: Some(next_request_json.clone()),
            }
        }
        V17AgentToolPath::Completed
        | V17AgentToolPath::Queued
        | V17AgentToolPath::Started
        | V17AgentToolPath::LegacyTerminal => {
            store
                .complete_agent_model_success(AgentModelSuccessCommit {
                    job_id: job.id,
                    response_json: agent_tool_response_json(&call),
                    resolution: AgentModelResolution::ToolCall { call: call.clone() },
                })
                .await
                .unwrap();
            if matches!(
                path,
                V17AgentToolPath::Completed
                    | V17AgentToolPath::Started
                    | V17AgentToolPath::LegacyTerminal
            ) {
                let AgentToolClaimOutcome::Claimed(_) = store
                    .claim_next_agent_tool(&test_agent_manifest())
                    .await
                    .unwrap()
                else {
                    panic!("the {label} tool must be claimable");
                };
            }
            let commit = AgentToolCompletionCommit {
                call_id: call.call_id.clone(),
                status: AgentToolCallStatus::Succeeded,
                result_json: json!({"path": label, "ok": true}),
                provider_request_id: Some(format!("connector-v17-{label}")),
                next_request_json: if matches!(path, V17AgentToolPath::LegacyTerminal) {
                    None
                } else {
                    Some(next_request_json.clone())
                },
            };
            if matches!(path, V17AgentToolPath::LegacyTerminal) {
                let completion = store.complete_agent_tool(commit.clone()).await.unwrap();
                assert!(matches!(completion, AgentToolCompletion::Terminal(_)));
            } else if matches!(path, V17AgentToolPath::Completed) {
                let completion = store.complete_agent_tool(commit.clone()).await.unwrap();
                assert!(matches!(
                    completion,
                    AgentToolCompletion::ModelQueued { .. }
                ));
            }
            commit
        }
    };
    drop(store);
    downgrade_agent_tool_completion_replay_fixture_to_v17(database.path());
    V17AgentToolPathFixture {
        database,
        call_id: call.call_id,
        turn_id,
        tool_replay,
        model_replay,
        review_replay,
    }
}

struct AgentToolReplayBindingRow {
    status: String,
    started: bool,
    finished: bool,
    has_result: bool,
    has_next_job: bool,
    binding: Option<Value>,
}

fn agent_tool_replay_binding_row(path: &Path, call_id: &str) -> AgentToolReplayBindingRow {
    let connection = rusqlite::Connection::open(path).unwrap();
    let (status, started, finished, has_result, has_next_job, binding): (
        String,
        i64,
        i64,
        i64,
        i64,
        Option<String>,
    ) = connection
        .query_row(
            r#"SELECT call.status,
                      call.started_at IS NOT NULL,
                      call.finished_at IS NOT NULL,
                      call.result_json IS NOT NULL,
                      EXISTS(
                          SELECT 1 FROM agent_model_jobs job
                          WHERE job.agent_id = call.agent_id
                            AND job.step = call.model_step + 1
                      ),
                      call.completion_next_request_json
               FROM agent_tool_calls call WHERE call.call_id = ?1"#,
            [call_id],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                ))
            },
        )
        .unwrap();
    AgentToolReplayBindingRow {
        status,
        started: started != 0,
        finished: finished != 0,
        has_result: has_result != 0,
        has_next_job: has_next_job != 0,
        binding: binding.map(|value| serde_json::from_str(&value).unwrap()),
    }
}

fn downgrade_agent_tool_completion_replay_fixture_to_v17(path: &Path) {
    let connection = rusqlite::Connection::open(path).unwrap();
    downgrade_agent_deployment_manifest_fixture_to_v18(&connection);
    connection
        .execute_batch(
            r#"DROP TRIGGER agent_tool_calls_require_completion_next_request;
               DROP TRIGGER agent_tool_calls_freeze_completion_next_request;
               DROP TRIGGER agent_model_jobs_bind_tool_completion_request;
               ALTER TABLE agent_tool_calls DROP COLUMN completion_next_request_json;
               DELETE FROM schema_migrations WHERE version = 18;"#,
        )
        .unwrap();
}

async fn v18_waiting_approval_manifest_fixture(
    decision: &str,
) -> (TestDatabase, ManifestEnvelope, AgentToolCallSpec) {
    let database = TestDatabase::new();
    let store = created_owned_file_session_store(database.path()).await;
    let manifest = test_agent_manifest();
    let turn_id = format!("turn-v18-manifest-approval-{decision}");
    store
        .start_turn_and_enqueue_agent_for_actor(
            &owner_authz(),
            "session-alpha",
            StartTurnRequest {
                turn_id: turn_id.clone(),
                user_message: "Preserve a legacy pending approval across v19 migration".into(),
                expected_sequence: 1,
            },
            &format!("v18-manifest-approval-{decision}-start"),
            agent_turn_spec_with_manifest(
                &format!("agent-v18-manifest-approval-{decision}"),
                &turn_id,
                manifest.clone(),
            ),
        )
        .await
        .unwrap();
    let AgentModelClaimOutcome::Claimed(job) =
        store.claim_next_agent_model(&manifest).await.unwrap()
    else {
        panic!("the pre-downgrade approval model must be claimable");
    };
    let call = agent_tool_call_spec(
        &format!("agent-call-v18-manifest-approval-{decision}"),
        PolicyDecision::RequireApproval,
    );
    store
        .complete_agent_model_success(AgentModelSuccessCommit {
            job_id: job.id,
            response_json: agent_tool_response_json(&call),
            resolution: AgentModelResolution::ToolCall { call: call.clone() },
        })
        .await
        .unwrap();
    drop(store);
    let connection = rusqlite::Connection::open(database.path()).unwrap();
    downgrade_agent_deployment_manifest_fixture_to_v18(&connection);
    drop(connection);
    (database, manifest, call)
}

fn downgrade_agent_deployment_manifest_fixture_to_v18(connection: &rusqlite::Connection) {
    let version: i64 = connection
        .query_row("SELECT MAX(version) FROM schema_migrations", [], |row| {
            row.get(0)
        })
        .unwrap();
    if version >= 20 {
        drop_v20_fixture_objects(connection);
    }
    connection
        .execute_batch(
            r#"DROP TRIGGER agent_turns_require_deployment_manifest;
               DROP TRIGGER agent_deployment_manifests_reject_update;
               DROP TRIGGER agent_deployment_manifests_reject_delete;
               DROP TRIGGER agent_turns_reject_identity_update;
               DROP INDEX agent_turns_deployment_manifest_idx;
               ALTER TABLE agent_turns DROP COLUMN deployment_manifest_digest;
               DROP TABLE agent_deployment_manifests;
               CREATE TRIGGER agent_turns_reject_identity_update
               BEFORE UPDATE OF id, account_id, actor_user_id, actor_membership_revision,
                                session_id, turn_id, environment, provider_name, model_name,
                                created_at
               ON agent_turns
               BEGIN
                   SELECT RAISE(ABORT, 'agent turn identity is immutable');
               END;
               DELETE FROM schema_migrations WHERE version = 19;"#,
        )
        .unwrap();
}

fn drop_v20_fixture_objects(connection: &rusqlite::Connection) {
    let version: i64 = connection
        .query_row("SELECT MAX(version) FROM schema_migrations", [], |row| {
            row.get(0)
        })
        .unwrap();
    if version >= 21 {
        drop_v21_fixture_objects(connection);
    }
    let model_trigger = migration_trigger_sql(
        include_str!("../migrations/0017_session_agent_loop.sql"),
        "agent_model_jobs_enforce_forward_transition",
    );
    let tool_trigger = migration_trigger_sql(
        include_str!("../migrations/0018_agent_tool_completion_replay.sql"),
        "agent_tool_calls_enforce_forward_transition",
    );
    connection
        .execute_batch(
            r#"DROP TRIGGER schema_migrations_reject_update;
               DROP TRIGGER schema_migrations_reject_delete;
               DROP TRIGGER agent_model_jobs_enforce_forward_transition;
               DROP TRIGGER agent_tool_calls_enforce_forward_transition;
               DROP TABLE agent_execution_heads;
               DROP TABLE agent_execution_events;
               DROP TABLE agent_run_epochs;
               DELETE FROM schema_migrations WHERE version = 20;"#,
        )
        .unwrap();
    connection.execute_batch(model_trigger).unwrap();
    connection.execute_batch(tool_trigger).unwrap();
}

fn drop_v21_fixture_objects(connection: &rusqlite::Connection) {
    let reject_update = migration_trigger_sql(
        include_str!("../migrations/0020_agent_execution_ledger.sql"),
        "schema_migrations_reject_update",
    );
    let reject_delete = migration_trigger_sql(
        include_str!("../migrations/0020_agent_execution_ledger.sql"),
        "schema_migrations_reject_delete",
    );
    connection
        .execute_batch(
            r#"DROP TRIGGER schema_migrations_reject_update;
               DROP TRIGGER schema_migrations_reject_delete;
               DROP TABLE agent_operation_claims;
               DELETE FROM schema_migrations WHERE version = 21;"#,
        )
        .unwrap();
    connection.execute_batch(reject_update).unwrap();
    connection.execute_batch(reject_delete).unwrap();
}

fn migration_trigger_sql(migration: &'static str, name: &str) -> &'static str {
    let marker = format!("CREATE TRIGGER {name}\n");
    let start = migration
        .find(&marker)
        .unwrap_or_else(|| panic!("migration is missing trigger `{name}`"));
    let trigger = &migration[start..];
    let end = trigger
        .find("\nEND;")
        .unwrap_or_else(|| panic!("migration trigger `{name}` is unterminated"))
        + "\nEND;".len();
    &trigger[..end]
}

fn force_agent_tool_completion_binding(path: &Path, call_id: &str, binding_json: &str) {
    let connection = rusqlite::Connection::open(path).unwrap();
    let forward_trigger: String = connection
        .query_row(
            r#"SELECT sql FROM sqlite_schema
               WHERE type = 'trigger'
                 AND name = 'agent_tool_calls_enforce_forward_transition'"#,
            [],
            |row| row.get(0),
        )
        .unwrap();
    let binding_trigger: String = connection
        .query_row(
            r#"SELECT sql FROM sqlite_schema
               WHERE type = 'trigger'
                 AND name = 'agent_tool_calls_freeze_completion_next_request'"#,
            [],
            |row| row.get(0),
        )
        .unwrap();
    connection
        .execute_batch(
            r#"DROP TRIGGER agent_tool_calls_enforce_forward_transition;
               DROP TRIGGER agent_tool_calls_freeze_completion_next_request;
               PRAGMA ignore_check_constraints = ON;"#,
        )
        .unwrap();
    connection
        .execute(
            r#"UPDATE agent_tool_calls
               SET completion_next_request_json = ?1 WHERE call_id = ?2"#,
            params![binding_json, call_id],
        )
        .unwrap();
    connection
        .execute_batch("PRAGMA ignore_check_constraints = OFF;")
        .unwrap();
    connection.execute_batch(&forward_trigger).unwrap();
    connection.execute_batch(&binding_trigger).unwrap();
}

async fn assert_agent_tool_completion_binding_integrity_error(store: SqliteStore, path: &Path) {
    assert!(matches!(
        store.verify_integrity().await,
        Err(StorageError::CorruptData(message))
            if message.contains("tool completion replay bindings")
    ));
    drop(store);
    assert!(matches!(
        SqliteStore::open(path).await,
        Err(StorageError::CorruptData(message))
            if message.contains("tool completion replay bindings")
    ));
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

async fn seeded_file_store_with_operation_limits(
    path: &Path,
    operation_limits: SqliteOperationLimits,
) -> SqliteStore {
    let store = operation_limited_store(path, operation_limits).await;
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
        initiating_authz: Some(owner_authz()),
        approving_authz: owner_authz(),
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

fn create_v5_database_with_owner(path: &Path) {
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
    ] {
        connection.execute_batch(migration).unwrap();
        connection
            .execute(
                "INSERT INTO schema_migrations(version, applied_at) VALUES (?1, ?2)",
                params![version, format!("2026-08-26T00:00:0{version}.000Z")],
            )
            .unwrap();
    }
    connection
        .execute(
            r#"INSERT INTO users(
                   id, username, role, status, password_hash, created_at, updated_at
               ) VALUES (
                   'user-v5-owner', 'v5-owner', 'owner', 'active',
                   '$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$ZGlnaWVzdA',
                   '2026-08-26T00:00:05.000Z', '2026-08-26T00:00:05.000Z'
               )"#,
            [],
        )
        .unwrap();
    connection
        .execute(
            r#"INSERT INTO user_preferences(user_id, theme, revision, updated_at)
               VALUES (
                   'user-v5-owner', 'system', 1, '2026-08-26T00:00:05.000Z'
               )"#,
            [],
        )
        .unwrap();
    connection
        .execute(
            "UPDATE sessions SET owner_user_id = 'user-v5-owner' WHERE owner_user_id IS NULL",
            [],
        )
        .unwrap();
    connection
        .execute(
            "UPDATE runs SET owner_user_id = 'user-v5-owner' WHERE owner_user_id IS NULL",
            [],
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
    let has_account_scope: i64 = connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM pragma_table_info('incidents') WHERE name = 'account_id')",
            [],
            |row| row.get(0),
        )
        .unwrap();
    if has_account_scope == 1 {
        connection
            .execute(
                r#"INSERT INTO incidents(
                       id, title, severity, status, service, region, user_impact, since,
                       account_id
                   ) VALUES (
                       'INC-SECOND', 'Second incident', 'low', 'investigating',
                       'worker', 'local', 'none', '2026-08-26T02:00:00Z', 'acc_local'
                   )"#,
                [],
            )
            .unwrap();
        connection
            .execute(
                r#"INSERT INTO runs(
                       id, incident_id, status, environment, started_at, duration_seconds,
                       agent, sequence, projection_sequence, metrics_json, evidence_json,
                       tool_policy_json, execution_status, account_id
                   ) VALUES (
                       'ZR-SECOND', 'INC-SECOND', 'waiting_for_approval', 'production',
                       '2026-08-26T02:00:00Z', 0, 'Zeus Responder', 0, 0,
                       '[]', '[]', NULL, 'waiting_for_approval', 'acc_local'
                   )"#,
                [],
            )
            .unwrap();
    } else {
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
