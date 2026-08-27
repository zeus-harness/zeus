//! Owner-isolated persistent terminal lifecycle independent of any concrete
//! process or container implementation.
//!
//! The service never starts a host process. A deployment must register an
//! explicit backend whose own boundary satisfies the advertised sandbox. This
//! crate owns identity, lifecycle, concurrency, and result limits so every
//! backend receives the same fail-closed contract.

use std::{
    collections::{BTreeMap, BTreeSet},
    future::Future,
    path::{Component, Path},
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use serde::{Deserialize, Serialize};
use thiserror::Error;
use tools::ExecutionScope;

pub const MAX_TERMINAL_BACKEND_TYPE_BYTES: usize = 64;
pub const MAX_TERMINAL_NAME_BYTES: usize = 64;
pub const MAX_TERMINAL_CWD_BYTES: usize = 512;
pub const MAX_TERMINAL_INPUT_BYTES: usize = 16 * 1024;
pub const MAX_TERMINAL_RESULT_BYTES: usize = 48 * 1024;
pub const MAX_TERMINAL_READ_LINES: usize = 500;
pub const MAX_TERMINAL_SESSIONS_PER_OWNER: usize = 4;
pub const MAX_TERMINAL_SESSIONS: usize = 128;
pub const MAX_TERMINAL_BACKENDS: usize = 8;
pub const MAX_TERMINAL_DEADLINE: Duration = Duration::from_secs(5 * 60);
pub const DEFAULT_TERMINAL_SPAWN_DEADLINE: Duration = Duration::from_secs(60);
pub const DEFAULT_TERMINAL_SEND_DEADLINE: Duration = Duration::from_secs(45);
pub const DEFAULT_TERMINAL_CONTROL_DEADLINE: Duration = Duration::from_secs(10);
pub const DEFAULT_TERMINAL_CLEANUP_DEADLINE: Duration = Duration::from_secs(10);

pub type TerminalFuture<'a, T> =
    Pin<Box<dyn Future<Output = Result<T, TerminalError>> + Send + 'a>>;

/// Zeus-owned outer deadlines for calls into an isolated terminal backend.
/// A backend may apply stricter readiness or process deadlines of its own.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TerminalDeadlines {
    spawn: Duration,
    send: Duration,
    control: Duration,
    cleanup: Duration,
}

impl TerminalDeadlines {
    pub fn new(
        spawn: Duration,
        send: Duration,
        control: Duration,
        cleanup: Duration,
    ) -> Result<Self, TerminalError> {
        for deadline in [spawn, send, control, cleanup] {
            if deadline.is_zero() || deadline > MAX_TERMINAL_DEADLINE {
                return Err(TerminalError::InvalidDeadlineConfiguration);
            }
        }
        Ok(Self {
            spawn,
            send,
            control,
            cleanup,
        })
    }

    pub fn spawn(self) -> Duration {
        self.spawn
    }

    pub fn send(self) -> Duration {
        self.send
    }

    pub fn control(self) -> Duration {
        self.control
    }

    pub fn cleanup(self) -> Duration {
        self.cleanup
    }
}

impl Default for TerminalDeadlines {
    fn default() -> Self {
        Self {
            spawn: DEFAULT_TERMINAL_SPAWN_DEADLINE,
            send: DEFAULT_TERMINAL_SEND_DEADLINE,
            control: DEFAULT_TERMINAL_CONTROL_DEADLINE,
            cleanup: DEFAULT_TERMINAL_CLEANUP_DEADLINE,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum TerminalStatus {
    Running,
    Exited {
        exit_code: Option<i32>,
        signal: Option<String>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TerminalSnapshot {
    pub session_id: String,
    pub name: Option<String>,
    pub backend_type: String,
    pub status: TerminalStatus,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TerminalWaitReason {
    StdinRead,
    InferredIdle,
    Timeout,
    SessionExit,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TerminalSendResult {
    pub viewport: String,
    pub wait_reason: TerminalWaitReason,
    pub status: TerminalStatus,
    pub truncated: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TerminalReadResult {
    pub text: String,
    pub total_lines: usize,
    pub line_begin: usize,
    pub line_end: usize,
    pub truncated: bool,
}

/// Best-effort backend cleanup after Zeus has already committed an Agent
/// terminal state. Records are always removed from the service capacity;
/// failures report possible backend-side leakage without reopening the Agent.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TerminalCleanupReport {
    pub removed: usize,
    pub pending_cancelled: usize,
    pub close_attempted: usize,
    pub close_succeeded: usize,
    pub close_failed: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum TerminalSignal {
    #[serde(rename = "SIGINT")]
    Interrupt,
    #[serde(rename = "SIGTERM")]
    Terminate,
    #[serde(rename = "SIGKILL")]
    Kill,
    #[serde(rename = "SIGTSTP")]
    Stop,
    #[serde(rename = "SIGHUP")]
    Hangup,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TerminalSpawnRequest {
    pub backend_type: String,
    pub name: Option<String>,
    pub cwd: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BackendSpawnRequest {
    pub session_id: String,
    pub owner: ExecutionScope,
    pub cwd: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TerminalSendRequest {
    pub text: String,
    pub submit: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TerminalReadRequest {
    pub offset: usize,
    pub count: usize,
}

#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum TerminalError {
    #[error("terminal backend configuration is invalid")]
    InvalidBackendConfiguration,
    #[error("terminal deadline configuration is invalid")]
    InvalidDeadlineConfiguration,
    #[error("terminal request is invalid: {0}")]
    InvalidRequest(&'static str),
    #[error("terminal backend is unavailable")]
    BackendUnavailable,
    #[error("terminal owner session limit reached")]
    OwnerSessionLimit,
    #[error("terminal service session limit reached")]
    ServiceSessionLimit,
    #[error("terminal name is already in use by this owner")]
    DuplicateName,
    #[error("terminal session is unknown to this owner")]
    UnknownSession,
    #[error("terminal session is closing")]
    SessionClosing,
    #[error("terminal session already has a send in progress")]
    SendInProgress,
    #[error("terminal backend operation failed")]
    BackendFailed,
    #[error("terminal backend operation exceeded its Zeus deadline")]
    BackendTimedOut,
    #[error("terminal backend returned an invalid result")]
    InvalidBackendResult,
    #[error("terminal service state is unavailable")]
    StateUnavailable,
}

/// One live isolated terminal. Operation futures may be dropped when their
/// Zeus deadline expires; the session must remain closeable afterward.
pub trait TerminalBackendSession: Send + Sync {
    fn snapshot(&self) -> TerminalFuture<'_, TerminalStatus>;
    fn send(&self, request: TerminalSendRequest) -> TerminalFuture<'_, TerminalSendResult>;
    fn read(&self, request: TerminalReadRequest) -> TerminalFuture<'_, TerminalReadResult>;
    fn signal(&self, signal: TerminalSignal) -> TerminalFuture<'_, TerminalStatus>;
    fn close(&self) -> TerminalFuture<'_, ()>;
}

pub trait TerminalBackend: Send + Sync {
    fn backend_type(&self) -> &str;
    /// Create one unpublished session. Dropping this future is cancellation;
    /// the backend must reclaim any partial resources that it has not returned.
    fn spawn(
        &self,
        request: BackendSpawnRequest,
    ) -> TerminalFuture<'_, Arc<dyn TerminalBackendSession>>;
}

struct TerminalRecord {
    owner: ExecutionScope,
    name: Option<String>,
    backend_type: String,
    session: Arc<dyn TerminalBackendSession>,
    send_in_progress: AtomicBool,
    closing: AtomicBool,
}

#[derive(Default)]
struct TerminalState {
    next_session: u64,
    sessions: BTreeMap<String, Arc<TerminalRecord>>,
    pending_names: BTreeSet<(ExecutionScope, String)>,
    pending_by_owner: BTreeMap<ExecutionScope, usize>,
    closing_owners: BTreeSet<ExecutionScope>,
    pending_total: usize,
}

pub struct TerminalService {
    backends: BTreeMap<String, Arc<dyn TerminalBackend>>,
    state: Arc<Mutex<TerminalState>>,
    deadlines: TerminalDeadlines,
}

impl TerminalService {
    pub fn new(
        backends: impl IntoIterator<Item = Arc<dyn TerminalBackend>>,
    ) -> Result<Self, TerminalError> {
        Self::with_deadlines(backends, TerminalDeadlines::default())
    }

    pub fn with_deadlines(
        backends: impl IntoIterator<Item = Arc<dyn TerminalBackend>>,
        deadlines: TerminalDeadlines,
    ) -> Result<Self, TerminalError> {
        TerminalDeadlines::new(
            deadlines.spawn,
            deadlines.send,
            deadlines.control,
            deadlines.cleanup,
        )?;
        let mut registered = BTreeMap::new();
        for backend in backends {
            let backend_type = backend.backend_type();
            validate_identifier(backend_type, MAX_TERMINAL_BACKEND_TYPE_BYTES)
                .map_err(|_| TerminalError::InvalidBackendConfiguration)?;
            if registered.len() == MAX_TERMINAL_BACKENDS
                || registered
                    .insert(backend_type.to_owned(), backend)
                    .is_some()
            {
                return Err(TerminalError::InvalidBackendConfiguration);
            }
        }
        if registered.is_empty() {
            return Err(TerminalError::InvalidBackendConfiguration);
        }
        Ok(Self {
            backends: registered,
            state: Arc::new(Mutex::new(TerminalState {
                next_session: 1,
                ..TerminalState::default()
            })),
            deadlines,
        })
    }

    pub fn backend_types(&self) -> Vec<String> {
        self.backends.keys().cloned().collect()
    }

    pub fn deadlines(&self) -> TerminalDeadlines {
        self.deadlines
    }

    pub async fn spawn(
        &self,
        owner: ExecutionScope,
        request: TerminalSpawnRequest,
    ) -> Result<TerminalSnapshot, TerminalError> {
        validate_spawn_request(&request)?;
        let backend = Arc::clone(
            self.backends
                .get(&request.backend_type)
                .ok_or(TerminalError::BackendUnavailable)?,
        );
        let mut reservation = SpawnReservation::acquire(
            Arc::clone(&self.state),
            owner.clone(),
            request.name.clone(),
        )?;
        let session_id = reservation.session_id.clone();
        let spawn_deadline = tokio::time::Instant::now() + self.deadlines.spawn;
        let session = await_backend_at(
            spawn_deadline,
            backend.spawn(BackendSpawnRequest {
                session_id: session_id.clone(),
                owner: owner.clone(),
                cwd: request.cwd,
            }),
        )
        .await?;
        let status = match await_backend_at(spawn_deadline, session.snapshot()).await {
            Ok(status) if validate_status(&status).is_ok() => status,
            Ok(_) => {
                let _ = await_backend(self.deadlines.cleanup, session.close()).await;
                return Err(TerminalError::InvalidBackendResult);
            }
            Err(error) => {
                let _ = await_backend(self.deadlines.cleanup, session.close()).await;
                return Err(error);
            }
        };
        let record = Arc::new(TerminalRecord {
            owner,
            name: request.name.clone(),
            backend_type: request.backend_type.clone(),
            session,
            send_in_progress: AtomicBool::new(false),
            closing: AtomicBool::new(false),
        });
        if let Err(error) = reservation.publish(Arc::clone(&record)) {
            await_backend(self.deadlines.cleanup, record.session.close()).await?;
            return Err(error);
        }
        Ok(snapshot_for(&session_id, &record, status))
    }

    pub async fn list(
        &self,
        owner: &ExecutionScope,
    ) -> Result<Vec<TerminalSnapshot>, TerminalError> {
        let records = {
            let state = self
                .state
                .lock()
                .map_err(|_| TerminalError::StateUnavailable)?;
            state
                .sessions
                .iter()
                .filter(|(_, record)| {
                    record.owner == *owner && !record.closing.load(Ordering::Acquire)
                })
                .map(|(id, record)| (id.clone(), Arc::clone(record)))
                .collect::<Vec<_>>()
        };
        match tokio::time::timeout(self.deadlines.control, async {
            let mut snapshots = Vec::with_capacity(records.len());
            for (id, record) in records {
                let status = record
                    .session
                    .snapshot()
                    .await
                    .map_err(|_| TerminalError::BackendFailed)?;
                validate_status(&status)?;
                snapshots.push(snapshot_for(&id, &record, status));
            }
            snapshots.sort_by(|left, right| left.session_id.cmp(&right.session_id));
            Ok(snapshots)
        })
        .await
        {
            Ok(result) => result,
            Err(_) => Err(TerminalError::BackendTimedOut),
        }
    }

    pub async fn send(
        &self,
        owner: &ExecutionScope,
        session_id: &str,
        request: TerminalSendRequest,
    ) -> Result<TerminalSendResult, TerminalError> {
        validate_session_id(session_id)?;
        if request.text.len() > MAX_TERMINAL_INPUT_BYTES {
            return Err(TerminalError::InvalidRequest("terminal input is too large"));
        }
        let record = self.owned_record(owner, session_id)?;
        if record.closing.load(Ordering::Acquire) {
            return Err(TerminalError::SessionClosing);
        }
        let _send = SendGuard::acquire(&record.send_in_progress)?;
        let result = await_backend(self.deadlines.send, record.session.send(request)).await?;
        validate_send_result(&result)?;
        Ok(result)
    }

    pub async fn read(
        &self,
        owner: &ExecutionScope,
        session_id: &str,
        request: TerminalReadRequest,
    ) -> Result<TerminalReadResult, TerminalError> {
        validate_session_id(session_id)?;
        if request.count == 0 || request.count > MAX_TERMINAL_READ_LINES {
            return Err(TerminalError::InvalidRequest(
                "terminal read count is outside its limit",
            ));
        }
        let record = self.owned_record(owner, session_id)?;
        if record.closing.load(Ordering::Acquire) {
            return Err(TerminalError::SessionClosing);
        }
        let result = await_backend(self.deadlines.control, record.session.read(request)).await?;
        validate_read_result(&result, request.count)?;
        Ok(result)
    }

    pub async fn signal(
        &self,
        owner: &ExecutionScope,
        session_id: &str,
        signal: TerminalSignal,
    ) -> Result<TerminalStatus, TerminalError> {
        validate_session_id(session_id)?;
        let record = self.owned_record(owner, session_id)?;
        if record.closing.load(Ordering::Acquire) {
            return Err(TerminalError::SessionClosing);
        }
        let status = await_backend(self.deadlines.control, record.session.signal(signal)).await?;
        validate_status(&status)?;
        Ok(status)
    }

    pub async fn close(
        &self,
        owner: &ExecutionScope,
        session_id: &str,
    ) -> Result<bool, TerminalError> {
        validate_session_id(session_id)?;
        let record = self.owned_record(owner, session_id)?;
        if record
            .closing
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Ok(false);
        }
        let result = await_backend(self.deadlines.cleanup, record.session.close()).await;
        let mut state = self
            .state
            .lock()
            .map_err(|_| TerminalError::StateUnavailable)?;
        state.sessions.remove(session_id);
        result.map_err(|_| TerminalError::BackendFailed)?;
        Ok(true)
    }

    /// Remove and best-effort close every terminal owned by one exact Agent
    /// execution scope. This is idempotent and does not expose foreign records.
    pub async fn close_owner(
        &self,
        owner: &ExecutionScope,
    ) -> Result<TerminalCleanupReport, TerminalError> {
        let records = {
            let mut state = self
                .state
                .lock()
                .map_err(|_| TerminalError::StateUnavailable)?;
            let pending_cancelled = state.pending_by_owner.get(owner).copied().unwrap_or(0);
            if pending_cancelled > 0 {
                state.closing_owners.insert(owner.clone());
            }
            let session_ids = state
                .sessions
                .iter()
                .filter(|(_, record)| record.owner == *owner)
                .map(|(session_id, _)| session_id.clone())
                .collect::<Vec<_>>();
            let records = session_ids
                .into_iter()
                .filter_map(|session_id| {
                    state
                        .sessions
                        .remove(&session_id)
                        .map(|record| (session_id, record))
                })
                .collect::<Vec<_>>();
            (records, pending_cancelled)
        };
        let mut report = TerminalCleanupReport {
            removed: records.0.len(),
            pending_cancelled: records.1,
            ..TerminalCleanupReport::default()
        };
        let mut cleanups = tokio::task::JoinSet::new();
        for (_, record) in records.0 {
            if record
                .closing
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .is_err()
            {
                continue;
            }
            report.close_attempted += 1;
            cleanups.spawn(async move { record.session.close().await });
        }
        let cleanup_deadline = tokio::time::Instant::now() + self.deadlines.cleanup;
        while report.close_succeeded + report.close_failed < report.close_attempted {
            match tokio::time::timeout_at(cleanup_deadline, cleanups.join_next()).await {
                Ok(Some(Ok(Ok(())))) => report.close_succeeded += 1,
                Ok(Some(Ok(Err(_))) | Some(Err(_))) => report.close_failed += 1,
                Ok(None) => {
                    report.close_failed = report.close_attempted - report.close_succeeded;
                    break;
                }
                Err(_) => {
                    report.close_failed = report.close_attempted - report.close_succeeded;
                    cleanups.abort_all();
                    break;
                }
            }
        }
        Ok(report)
    }

    fn owned_record(
        &self,
        owner: &ExecutionScope,
        session_id: &str,
    ) -> Result<Arc<TerminalRecord>, TerminalError> {
        let state = self
            .state
            .lock()
            .map_err(|_| TerminalError::StateUnavailable)?;
        let record = state
            .sessions
            .get(session_id)
            .filter(|record| record.owner == *owner)
            .ok_or(TerminalError::UnknownSession)?;
        Ok(Arc::clone(record))
    }
}

async fn await_backend<T>(
    deadline: Duration,
    operation: impl Future<Output = Result<T, TerminalError>>,
) -> Result<T, TerminalError> {
    await_backend_at(tokio::time::Instant::now() + deadline, operation).await
}

async fn await_backend_at<T>(
    deadline: tokio::time::Instant,
    operation: impl Future<Output = Result<T, TerminalError>>,
) -> Result<T, TerminalError> {
    match tokio::time::timeout_at(deadline, operation).await {
        Ok(Ok(result)) => Ok(result),
        Ok(Err(_)) => Err(TerminalError::BackendFailed),
        Err(_) => Err(TerminalError::BackendTimedOut),
    }
}

struct SpawnReservation {
    state: Arc<Mutex<TerminalState>>,
    owner: ExecutionScope,
    name: Option<String>,
    session_id: String,
    active: bool,
}

impl SpawnReservation {
    fn acquire(
        state: Arc<Mutex<TerminalState>>,
        owner: ExecutionScope,
        name: Option<String>,
    ) -> Result<Self, TerminalError> {
        let session_id = {
            let mut current = state.lock().map_err(|_| TerminalError::StateUnavailable)?;
            let sequence = current.next_session;
            let next_session = sequence
                .checked_add(1)
                .ok_or(TerminalError::StateUnavailable)?;
            if current.closing_owners.contains(&owner) {
                return Err(TerminalError::SessionClosing);
            }
            let existing = current
                .sessions
                .values()
                .filter(|record| record.owner == owner)
                .count();
            let pending = current.pending_by_owner.get(&owner).copied().unwrap_or(0);
            if current.sessions.len() + current.pending_total >= MAX_TERMINAL_SESSIONS {
                return Err(TerminalError::ServiceSessionLimit);
            }
            if existing + pending >= MAX_TERMINAL_SESSIONS_PER_OWNER {
                return Err(TerminalError::OwnerSessionLimit);
            }
            if let Some(name) = &name {
                let duplicate_live = current.sessions.values().any(|record| {
                    record.owner == owner && record.name.as_deref() == Some(name.as_str())
                });
                if duplicate_live || !current.pending_names.insert((owner.clone(), name.clone())) {
                    return Err(TerminalError::DuplicateName);
                }
            }
            *current.pending_by_owner.entry(owner.clone()).or_default() += 1;
            current.pending_total += 1;
            current.next_session = next_session;
            format!("pty-{sequence}")
        };
        Ok(Self {
            state,
            owner,
            name,
            session_id,
            active: true,
        })
    }

    fn publish(&mut self, record: Arc<TerminalRecord>) -> Result<(), TerminalError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| TerminalError::StateUnavailable)?;
        if state.closing_owners.contains(&self.owner) {
            return Err(TerminalError::SessionClosing);
        }
        if state.sessions.contains_key(&self.session_id) {
            return Err(TerminalError::StateUnavailable);
        }
        release_pending(&mut state, &self.owner, self.name.as_deref());
        state.sessions.insert(self.session_id.clone(), record);
        self.active = false;
        Ok(())
    }
}

impl Drop for SpawnReservation {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        if let Ok(mut state) = self.state.lock() {
            release_pending(&mut state, &self.owner, self.name.as_deref());
        }
    }
}

struct SendGuard<'a>(&'a AtomicBool);

impl<'a> SendGuard<'a> {
    fn acquire(flag: &'a AtomicBool) -> Result<Self, TerminalError> {
        flag.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| TerminalError::SendInProgress)?;
        Ok(Self(flag))
    }
}

impl Drop for SendGuard<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

fn release_pending(state: &mut TerminalState, owner: &ExecutionScope, name: Option<&str>) {
    if let Some(name) = name {
        state
            .pending_names
            .remove(&(owner.clone(), name.to_owned()));
    }
    let remove_owner = if let Some(count) = state.pending_by_owner.get_mut(owner) {
        *count = count.saturating_sub(1);
        *count == 0
    } else {
        false
    };
    if remove_owner {
        state.pending_by_owner.remove(owner);
        state.closing_owners.remove(owner);
    }
    state.pending_total = state.pending_total.saturating_sub(1);
}

fn snapshot_for(
    session_id: &str,
    record: &TerminalRecord,
    status: TerminalStatus,
) -> TerminalSnapshot {
    TerminalSnapshot {
        session_id: session_id.to_owned(),
        name: record.name.clone(),
        backend_type: record.backend_type.clone(),
        status,
    }
}

fn validate_spawn_request(request: &TerminalSpawnRequest) -> Result<(), TerminalError> {
    validate_identifier(&request.backend_type, MAX_TERMINAL_BACKEND_TYPE_BYTES)?;
    if let Some(name) = &request.name
        && (name.is_empty()
            || name.len() > MAX_TERMINAL_NAME_BYTES
            || name.trim() != name
            || name.chars().any(char::is_control))
    {
        return Err(TerminalError::InvalidRequest("terminal name is invalid"));
    }
    validate_cwd(&request.cwd)
}

fn validate_identifier(value: &str, max_bytes: usize) -> Result<(), TerminalError> {
    if value.is_empty()
        || value.len() > max_bytes
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(TerminalError::InvalidRequest(
            "terminal identifier is invalid",
        ));
    }
    Ok(())
}

fn validate_cwd(cwd: &str) -> Result<(), TerminalError> {
    if cwd == "." {
        return Ok(());
    }
    if cwd.is_empty()
        || cwd.len() > MAX_TERMINAL_CWD_BYTES
        || cwd.trim() != cwd
        || cwd.contains('\\')
        || cwd.chars().any(char::is_control)
    {
        return Err(TerminalError::InvalidRequest("terminal cwd is invalid"));
    }
    let mut parts = Vec::new();
    for component in Path::new(cwd).components() {
        match component {
            Component::Normal(part) => {
                let part = part
                    .to_str()
                    .ok_or(TerminalError::InvalidRequest("terminal cwd is invalid"))?;
                parts.push(part);
            }
            _ => return Err(TerminalError::InvalidRequest("terminal cwd is invalid")),
        }
    }
    if parts.is_empty() || parts.join("/") != cwd {
        return Err(TerminalError::InvalidRequest("terminal cwd is invalid"));
    }
    Ok(())
}

fn validate_session_id(session_id: &str) -> Result<(), TerminalError> {
    validate_identifier(session_id, 64)
        .map_err(|_| TerminalError::InvalidRequest("terminal session id is invalid"))
}

fn validate_status(status: &TerminalStatus) -> Result<(), TerminalError> {
    if let TerminalStatus::Exited { signal, .. } = status
        && signal.as_ref().is_some_and(|signal| {
            signal.is_empty()
                || signal.len() > 32
                || !signal.bytes().all(|byte| byte.is_ascii_uppercase())
        })
    {
        return Err(TerminalError::InvalidBackendResult);
    }
    Ok(())
}

fn validate_send_result(result: &TerminalSendResult) -> Result<(), TerminalError> {
    if result.viewport.len() > MAX_TERMINAL_RESULT_BYTES {
        return Err(TerminalError::InvalidBackendResult);
    }
    validate_status(&result.status)
}

fn validate_read_result(
    result: &TerminalReadResult,
    requested_count: usize,
) -> Result<(), TerminalError> {
    if result.text.len() > MAX_TERMINAL_RESULT_BYTES
        || result.line_begin > result.line_end
        || result.line_end > result.total_lines
        || result.line_end - result.line_begin > requested_count
    {
        return Err(TerminalError::InvalidBackendResult);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    use super::*;

    struct StubBackend {
        sessions: Arc<Mutex<Vec<Arc<StubSession>>>>,
        fail_close: bool,
    }

    struct StubSession {
        sends: AtomicUsize,
        signals: AtomicUsize,
        closes: AtomicUsize,
        fail_close: bool,
    }

    struct BlockingSpawnBackend {
        entered: Arc<tokio::sync::Notify>,
        release: Arc<tokio::sync::Notify>,
        block_first: AtomicBool,
        sessions: Arc<Mutex<Vec<Arc<StubSession>>>>,
    }

    struct HangingBackend {
        session: Arc<HangingSession>,
    }

    struct HangingSession {
        hang_snapshot: AtomicBool,
        hang_send_once: AtomicBool,
        hang_close: AtomicBool,
        closes: AtomicUsize,
    }

    impl TerminalBackend for BlockingSpawnBackend {
        fn backend_type(&self) -> &str {
            "blocking"
        }

        fn spawn(
            &self,
            _request: BackendSpawnRequest,
        ) -> TerminalFuture<'_, Arc<dyn TerminalBackendSession>> {
            let entered = Arc::clone(&self.entered);
            let release = Arc::clone(&self.release);
            let should_block = self.block_first.swap(false, Ordering::AcqRel);
            let sessions = Arc::clone(&self.sessions);
            Box::pin(async move {
                if should_block {
                    entered.notify_one();
                    release.notified().await;
                }
                let session = Arc::new(StubSession {
                    sends: AtomicUsize::new(0),
                    signals: AtomicUsize::new(0),
                    closes: AtomicUsize::new(0),
                    fail_close: false,
                });
                sessions.lock().unwrap().push(Arc::clone(&session));
                let session: Arc<dyn TerminalBackendSession> = session;
                Ok(session)
            })
        }
    }

    impl TerminalBackend for StubBackend {
        fn backend_type(&self) -> &str {
            "stub"
        }

        fn spawn(
            &self,
            _request: BackendSpawnRequest,
        ) -> TerminalFuture<'_, Arc<dyn TerminalBackendSession>> {
            let session = Arc::new(StubSession {
                sends: AtomicUsize::new(0),
                signals: AtomicUsize::new(0),
                closes: AtomicUsize::new(0),
                fail_close: self.fail_close,
            });
            self.sessions.lock().unwrap().push(Arc::clone(&session));
            let backend_session: Arc<dyn TerminalBackendSession> = session;
            Box::pin(async move { Ok(backend_session) })
        }
    }

    impl TerminalBackend for HangingBackend {
        fn backend_type(&self) -> &str {
            "hanging"
        }

        fn spawn(
            &self,
            _request: BackendSpawnRequest,
        ) -> TerminalFuture<'_, Arc<dyn TerminalBackendSession>> {
            let session: Arc<dyn TerminalBackendSession> = self.session.clone();
            Box::pin(async move { Ok(session) })
        }
    }

    impl TerminalBackendSession for StubSession {
        fn snapshot(&self) -> TerminalFuture<'_, TerminalStatus> {
            Box::pin(async { Ok(TerminalStatus::Running) })
        }

        fn send(&self, request: TerminalSendRequest) -> TerminalFuture<'_, TerminalSendResult> {
            self.sends.fetch_add(1, Ordering::Relaxed);
            Box::pin(async move {
                Ok(TerminalSendResult {
                    viewport: format!("ran:{}:{}", request.text, request.submit),
                    wait_reason: TerminalWaitReason::InferredIdle,
                    status: TerminalStatus::Running,
                    truncated: false,
                })
            })
        }

        fn read(&self, request: TerminalReadRequest) -> TerminalFuture<'_, TerminalReadResult> {
            Box::pin(async move {
                Ok(TerminalReadResult {
                    text: "history".into(),
                    total_lines: 1,
                    line_begin: request.offset.min(1),
                    line_end: 1,
                    truncated: false,
                })
            })
        }

        fn signal(&self, _signal: TerminalSignal) -> TerminalFuture<'_, TerminalStatus> {
            self.signals.fetch_add(1, Ordering::Relaxed);
            Box::pin(async { Ok(TerminalStatus::Running) })
        }

        fn close(&self) -> TerminalFuture<'_, ()> {
            self.closes.fetch_add(1, Ordering::Relaxed);
            let fail_close = self.fail_close;
            Box::pin(async move {
                if fail_close {
                    Err(TerminalError::BackendFailed)
                } else {
                    Ok(())
                }
            })
        }
    }

    impl TerminalBackendSession for HangingSession {
        fn snapshot(&self) -> TerminalFuture<'_, TerminalStatus> {
            let hangs = self.hang_snapshot.load(Ordering::Acquire);
            Box::pin(async move {
                if hangs {
                    std::future::pending::<Result<TerminalStatus, TerminalError>>().await
                } else {
                    Ok(TerminalStatus::Running)
                }
            })
        }

        fn send(&self, request: TerminalSendRequest) -> TerminalFuture<'_, TerminalSendResult> {
            let hangs = self.hang_send_once.swap(false, Ordering::AcqRel);
            Box::pin(async move {
                if hangs {
                    std::future::pending::<Result<TerminalSendResult, TerminalError>>().await
                } else {
                    Ok(TerminalSendResult {
                        viewport: format!("ran:{}:{}", request.text, request.submit),
                        wait_reason: TerminalWaitReason::InferredIdle,
                        status: TerminalStatus::Running,
                        truncated: false,
                    })
                }
            })
        }

        fn read(&self, request: TerminalReadRequest) -> TerminalFuture<'_, TerminalReadResult> {
            Box::pin(async move {
                Ok(TerminalReadResult {
                    text: "history".into(),
                    total_lines: 1,
                    line_begin: request.offset.min(1),
                    line_end: 1,
                    truncated: false,
                })
            })
        }

        fn signal(&self, _signal: TerminalSignal) -> TerminalFuture<'_, TerminalStatus> {
            Box::pin(async { Ok(TerminalStatus::Running) })
        }

        fn close(&self) -> TerminalFuture<'_, ()> {
            self.closes.fetch_add(1, Ordering::Relaxed);
            let hangs = self.hang_close.load(Ordering::Acquire);
            Box::pin(async move {
                if hangs {
                    std::future::pending::<Result<(), TerminalError>>().await
                } else {
                    Ok(())
                }
            })
        }
    }

    fn owner(actor: &str) -> ExecutionScope {
        ExecutionScope::new("account-1", actor, "session-1", "turn-1", "agent-1").unwrap()
    }

    fn service() -> (TerminalService, Arc<Mutex<Vec<Arc<StubSession>>>>) {
        let sessions = Arc::new(Mutex::new(Vec::new()));
        let backend: Arc<dyn TerminalBackend> = Arc::new(StubBackend {
            sessions: Arc::clone(&sessions),
            fail_close: false,
        });
        (TerminalService::new([backend]).unwrap(), sessions)
    }

    fn test_deadlines() -> TerminalDeadlines {
        TerminalDeadlines::new(
            Duration::from_millis(25),
            Duration::from_millis(25),
            Duration::from_millis(25),
            Duration::from_millis(25),
        )
        .unwrap()
    }

    #[tokio::test]
    async fn complete_lifecycle_is_owner_isolated_and_bounded() {
        let (service, sessions) = service();
        let first = owner("user-1");
        let foreign = owner("user-2");
        let spawned = service
            .spawn(
                first.clone(),
                TerminalSpawnRequest {
                    backend_type: "stub".into(),
                    name: Some("main".into()),
                    cwd: ".".into(),
                },
            )
            .await
            .unwrap();
        assert_eq!(spawned.session_id, "pty-1");
        assert_eq!(service.list(&first).await.unwrap(), vec![spawned.clone()]);
        assert!(service.list(&foreign).await.unwrap().is_empty());
        assert_eq!(
            service
                .read(
                    &foreign,
                    &spawned.session_id,
                    TerminalReadRequest {
                        offset: 0,
                        count: 10,
                    },
                )
                .await,
            Err(TerminalError::UnknownSession)
        );
        let sent = service
            .send(
                &first,
                &spawned.session_id,
                TerminalSendRequest {
                    text: "echo hi".into(),
                    submit: true,
                },
            )
            .await
            .unwrap();
        assert_eq!(sent.viewport, "ran:echo hi:true");
        assert_eq!(
            service
                .read(
                    &first,
                    &spawned.session_id,
                    TerminalReadRequest {
                        offset: 0,
                        count: 10,
                    },
                )
                .await
                .unwrap()
                .text,
            "history"
        );
        assert_eq!(
            service
                .signal(&first, &spawned.session_id, TerminalSignal::Interrupt)
                .await
                .unwrap(),
            TerminalStatus::Running
        );
        assert!(service.close(&first, &spawned.session_id).await.unwrap());
        assert!(service.list(&first).await.unwrap().is_empty());
        assert_eq!(sessions.lock().unwrap()[0].sends.load(Ordering::Relaxed), 1);
        assert_eq!(
            sessions.lock().unwrap()[0].signals.load(Ordering::Relaxed),
            1
        );
        assert_eq!(
            sessions.lock().unwrap()[0].closes.load(Ordering::Relaxed),
            1
        );
    }

    #[tokio::test]
    async fn duplicate_names_limits_and_invalid_requests_fail_before_backend_work() {
        let (service, sessions) = service();
        let owner = owner("user-1");
        service
            .spawn(
                owner.clone(),
                TerminalSpawnRequest {
                    backend_type: "stub".into(),
                    name: Some("main".into()),
                    cwd: "src".into(),
                },
            )
            .await
            .unwrap();
        assert_eq!(
            service
                .spawn(
                    owner.clone(),
                    TerminalSpawnRequest {
                        backend_type: "stub".into(),
                        name: Some("main".into()),
                        cwd: ".".into(),
                    },
                )
                .await,
            Err(TerminalError::DuplicateName)
        );
        for index in 1..MAX_TERMINAL_SESSIONS_PER_OWNER {
            service
                .spawn(
                    owner.clone(),
                    TerminalSpawnRequest {
                        backend_type: "stub".into(),
                        name: Some(format!("term-{index}")),
                        cwd: ".".into(),
                    },
                )
                .await
                .unwrap();
        }
        assert_eq!(
            service
                .spawn(
                    owner.clone(),
                    TerminalSpawnRequest {
                        backend_type: "stub".into(),
                        name: None,
                        cwd: ".".into(),
                    },
                )
                .await,
            Err(TerminalError::OwnerSessionLimit)
        );
        assert_eq!(
            sessions.lock().unwrap().len(),
            MAX_TERMINAL_SESSIONS_PER_OWNER
        );
        assert_eq!(
            service
                .send(
                    &owner,
                    "pty-1",
                    TerminalSendRequest {
                        text: "x".repeat(MAX_TERMINAL_INPUT_BYTES + 1),
                        submit: true,
                    },
                )
                .await,
            Err(TerminalError::InvalidRequest("terminal input is too large"))
        );
    }

    #[tokio::test]
    async fn global_capacity_and_owner_cleanup_are_bounded_and_isolated() {
        let (service, sessions) = service();
        for index in 0..MAX_TERMINAL_SESSIONS {
            service
                .spawn(
                    owner(&format!("user-{index}")),
                    TerminalSpawnRequest {
                        backend_type: "stub".into(),
                        name: None,
                        cwd: ".".into(),
                    },
                )
                .await
                .unwrap();
        }
        assert_eq!(sessions.lock().unwrap().len(), MAX_TERMINAL_SESSIONS);
        assert_eq!(
            service
                .spawn(
                    owner("overflow"),
                    TerminalSpawnRequest {
                        backend_type: "stub".into(),
                        name: None,
                        cwd: ".".into(),
                    },
                )
                .await,
            Err(TerminalError::ServiceSessionLimit)
        );

        let first_owner = owner("user-0");
        let report = service.close_owner(&first_owner).await.unwrap();
        assert_eq!(
            report,
            TerminalCleanupReport {
                removed: 1,
                pending_cancelled: 0,
                close_attempted: 1,
                close_succeeded: 1,
                close_failed: 0,
            }
        );
        assert!(service.list(&first_owner).await.unwrap().is_empty());
        assert_eq!(service.list(&owner("user-1")).await.unwrap().len(), 1);
        assert_eq!(
            service.close_owner(&first_owner).await.unwrap(),
            TerminalCleanupReport::default()
        );

        service
            .spawn(
                owner("replacement"),
                TerminalSpawnRequest {
                    backend_type: "stub".into(),
                    name: None,
                    cwd: ".".into(),
                },
            )
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn owner_cleanup_releases_service_capacity_when_backend_close_fails() {
        let sessions = Arc::new(Mutex::new(Vec::new()));
        let backend: Arc<dyn TerminalBackend> = Arc::new(StubBackend {
            sessions: Arc::clone(&sessions),
            fail_close: true,
        });
        let service = TerminalService::new([backend]).unwrap();
        let owner = owner("close-failure");
        service
            .spawn(
                owner.clone(),
                TerminalSpawnRequest {
                    backend_type: "stub".into(),
                    name: None,
                    cwd: ".".into(),
                },
            )
            .await
            .unwrap();

        assert_eq!(
            service.close_owner(&owner).await.unwrap(),
            TerminalCleanupReport {
                removed: 1,
                pending_cancelled: 0,
                close_attempted: 1,
                close_succeeded: 0,
                close_failed: 1,
            }
        );
        assert!(service.list(&owner).await.unwrap().is_empty());
        assert_eq!(
            sessions.lock().unwrap()[0].closes.load(Ordering::Relaxed),
            1
        );
    }

    #[tokio::test]
    async fn owner_cleanup_cancels_an_in_flight_spawn_before_publication() {
        let entered = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new(tokio::sync::Notify::new());
        let sessions = Arc::new(Mutex::new(Vec::new()));
        let backend = Arc::new(BlockingSpawnBackend {
            entered: Arc::clone(&entered),
            release: Arc::clone(&release),
            block_first: AtomicBool::new(true),
            sessions: Arc::clone(&sessions),
        });
        let service = Arc::new(
            TerminalService::new([Arc::clone(&backend) as Arc<dyn TerminalBackend>]).unwrap(),
        );
        let owner = owner("spawn-cleanup");
        let entered_wait = entered.notified();
        let spawn = {
            let service = Arc::clone(&service);
            let owner = owner.clone();
            tokio::spawn(async move {
                service
                    .spawn(
                        owner,
                        TerminalSpawnRequest {
                            backend_type: "blocking".into(),
                            name: Some("main".into()),
                            cwd: ".".into(),
                        },
                    )
                    .await
            })
        };
        entered_wait.await;

        assert_eq!(
            service.close_owner(&owner).await.unwrap(),
            TerminalCleanupReport {
                removed: 0,
                pending_cancelled: 1,
                close_attempted: 0,
                close_succeeded: 0,
                close_failed: 0,
            }
        );
        assert_eq!(
            service
                .spawn(
                    owner.clone(),
                    TerminalSpawnRequest {
                        backend_type: "blocking".into(),
                        name: Some("replacement".into()),
                        cwd: ".".into(),
                    },
                )
                .await,
            Err(TerminalError::SessionClosing)
        );

        release.notify_one();
        assert_eq!(spawn.await.unwrap(), Err(TerminalError::SessionClosing));
        assert_eq!(
            sessions.lock().unwrap()[0].closes.load(Ordering::Relaxed),
            1
        );
        assert!(service.list(&owner).await.unwrap().is_empty());

        service
            .spawn(
                owner.clone(),
                TerminalSpawnRequest {
                    backend_type: "blocking".into(),
                    name: Some("replacement".into()),
                    cwd: ".".into(),
                },
            )
            .await
            .unwrap();
        assert_eq!(service.list(&owner).await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn spawn_deadline_releases_pending_name_and_capacity() {
        let backend = Arc::new(BlockingSpawnBackend {
            entered: Arc::new(tokio::sync::Notify::new()),
            release: Arc::new(tokio::sync::Notify::new()),
            block_first: AtomicBool::new(true),
            sessions: Arc::new(Mutex::new(Vec::new())),
        });
        let service = TerminalService::with_deadlines(
            [Arc::clone(&backend) as Arc<dyn TerminalBackend>],
            test_deadlines(),
        )
        .unwrap();
        let owner = owner("spawn-timeout");
        let request = TerminalSpawnRequest {
            backend_type: "blocking".into(),
            name: Some("main".into()),
            cwd: ".".into(),
        };

        assert_eq!(
            service.spawn(owner.clone(), request.clone()).await,
            Err(TerminalError::BackendTimedOut)
        );
        let replacement = service.spawn(owner.clone(), request).await.unwrap();
        assert_eq!(replacement.name.as_deref(), Some("main"));
        assert_eq!(service.list(&owner).await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn send_deadline_releases_the_exclusive_send_slot() {
        let session = Arc::new(HangingSession {
            hang_snapshot: AtomicBool::new(false),
            hang_send_once: AtomicBool::new(true),
            hang_close: AtomicBool::new(false),
            closes: AtomicUsize::new(0),
        });
        let service = TerminalService::with_deadlines(
            [Arc::new(HangingBackend {
                session: Arc::clone(&session),
            }) as Arc<dyn TerminalBackend>],
            test_deadlines(),
        )
        .unwrap();
        let owner = owner("send-timeout");
        let spawned = service
            .spawn(
                owner.clone(),
                TerminalSpawnRequest {
                    backend_type: "hanging".into(),
                    name: None,
                    cwd: ".".into(),
                },
            )
            .await
            .unwrap();
        let request = TerminalSendRequest {
            text: "echo bounded".into(),
            submit: true,
        };

        assert_eq!(
            service
                .send(&owner, &spawned.session_id, request.clone())
                .await,
            Err(TerminalError::BackendTimedOut)
        );
        assert_eq!(
            service
                .send(&owner, &spawned.session_id, request)
                .await
                .unwrap()
                .viewport,
            "ran:echo bounded:true"
        );
    }

    #[tokio::test]
    async fn list_uses_one_control_deadline_and_recovers_after_a_read_only_timeout() {
        let session = Arc::new(HangingSession {
            hang_snapshot: AtomicBool::new(false),
            hang_send_once: AtomicBool::new(false),
            hang_close: AtomicBool::new(false),
            closes: AtomicUsize::new(0),
        });
        let service = TerminalService::with_deadlines(
            [Arc::new(HangingBackend {
                session: Arc::clone(&session),
            }) as Arc<dyn TerminalBackend>],
            test_deadlines(),
        )
        .unwrap();
        let owner = owner("list-timeout");
        service
            .spawn(
                owner.clone(),
                TerminalSpawnRequest {
                    backend_type: "hanging".into(),
                    name: None,
                    cwd: ".".into(),
                },
            )
            .await
            .unwrap();

        session.hang_snapshot.store(true, Ordering::Release);
        assert_eq!(
            service.list(&owner).await,
            Err(TerminalError::BackendTimedOut)
        );
        session.hang_snapshot.store(false, Ordering::Release);
        assert_eq!(service.list(&owner).await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn owner_cleanup_has_one_total_deadline_for_all_backend_closes() {
        let session = Arc::new(HangingSession {
            hang_snapshot: AtomicBool::new(false),
            hang_send_once: AtomicBool::new(false),
            hang_close: AtomicBool::new(true),
            closes: AtomicUsize::new(0),
        });
        let service = TerminalService::with_deadlines(
            [Arc::new(HangingBackend {
                session: Arc::clone(&session),
            }) as Arc<dyn TerminalBackend>],
            test_deadlines(),
        )
        .unwrap();
        let owner = owner("cleanup-timeout");
        service
            .spawn(
                owner.clone(),
                TerminalSpawnRequest {
                    backend_type: "hanging".into(),
                    name: None,
                    cwd: ".".into(),
                },
            )
            .await
            .unwrap();

        let report = tokio::time::timeout(Duration::from_millis(250), service.close_owner(&owner))
            .await
            .expect("owner cleanup must not inherit an unbounded backend wait")
            .unwrap();
        assert_eq!(
            report,
            TerminalCleanupReport {
                removed: 1,
                pending_cancelled: 0,
                close_attempted: 1,
                close_succeeded: 0,
                close_failed: 1,
            }
        );
        assert_eq!(session.closes.load(Ordering::Relaxed), 1);
        assert!(service.list(&owner).await.unwrap().is_empty());
    }

    #[test]
    fn configuration_and_cwd_validation_fail_closed() {
        assert!(matches!(
            TerminalService::new(Vec::<Arc<dyn TerminalBackend>>::new()),
            Err(TerminalError::InvalidBackendConfiguration)
        ));
        for cwd in [
            "",
            "../outside",
            "/absolute",
            "./src",
            "src//nested",
            "src\\nested",
        ] {
            assert!(validate_cwd(cwd).is_err(), "cwd {cwd:?} must fail");
        }
        assert!(validate_cwd(".").is_ok());
        assert!(validate_cwd("src/nested").is_ok());
        assert_eq!(
            TerminalDeadlines::new(
                Duration::ZERO,
                DEFAULT_TERMINAL_SEND_DEADLINE,
                DEFAULT_TERMINAL_CONTROL_DEADLINE,
                DEFAULT_TERMINAL_CLEANUP_DEADLINE,
            ),
            Err(TerminalError::InvalidDeadlineConfiguration)
        );
        assert_eq!(
            TerminalDeadlines::new(
                MAX_TERMINAL_DEADLINE + Duration::from_millis(1),
                DEFAULT_TERMINAL_SEND_DEADLINE,
                DEFAULT_TERMINAL_CONTROL_DEADLINE,
                DEFAULT_TERMINAL_CLEANUP_DEADLINE,
            ),
            Err(TerminalError::InvalidDeadlineConfiguration)
        );
    }
}
