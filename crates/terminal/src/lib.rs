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
pub const MAX_TERMINAL_BACKENDS: usize = 8;

pub type TerminalFuture<'a, T> =
    Pin<Box<dyn Future<Output = Result<T, TerminalError>> + Send + 'a>>;

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
    #[error("terminal request is invalid: {0}")]
    InvalidRequest(&'static str),
    #[error("terminal backend is unavailable")]
    BackendUnavailable,
    #[error("terminal owner session limit reached")]
    OwnerSessionLimit,
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
    #[error("terminal backend returned an invalid result")]
    InvalidBackendResult,
    #[error("terminal service state is unavailable")]
    StateUnavailable,
}

pub trait TerminalBackendSession: Send + Sync {
    fn snapshot(&self) -> TerminalFuture<'_, TerminalStatus>;
    fn send(&self, request: TerminalSendRequest) -> TerminalFuture<'_, TerminalSendResult>;
    fn read(&self, request: TerminalReadRequest) -> TerminalFuture<'_, TerminalReadResult>;
    fn signal(&self, signal: TerminalSignal) -> TerminalFuture<'_, TerminalStatus>;
    fn close(&self) -> TerminalFuture<'_, ()>;
}

pub trait TerminalBackend: Send + Sync {
    fn backend_type(&self) -> &str;
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
}

pub struct TerminalService {
    backends: BTreeMap<String, Arc<dyn TerminalBackend>>,
    state: Arc<Mutex<TerminalState>>,
}

impl TerminalService {
    pub fn new(
        backends: impl IntoIterator<Item = Arc<dyn TerminalBackend>>,
    ) -> Result<Self, TerminalError> {
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
        })
    }

    pub fn backend_types(&self) -> Vec<String> {
        self.backends.keys().cloned().collect()
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
        let session = backend
            .spawn(BackendSpawnRequest {
                session_id: session_id.clone(),
                owner: owner.clone(),
                cwd: request.cwd,
            })
            .await
            .map_err(|_| TerminalError::BackendFailed)?;
        let status = match session.snapshot().await {
            Ok(status) if validate_status(&status).is_ok() => status,
            Ok(_) => {
                let _ = session.close().await;
                return Err(TerminalError::InvalidBackendResult);
            }
            Err(_) => {
                let _ = session.close().await;
                return Err(TerminalError::BackendFailed);
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
            let _ = record.session.close().await;
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
        let result = record
            .session
            .send(request)
            .await
            .map_err(|_| TerminalError::BackendFailed)?;
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
        let result = record
            .session
            .read(request)
            .await
            .map_err(|_| TerminalError::BackendFailed)?;
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
        let status = record
            .session
            .signal(signal)
            .await
            .map_err(|_| TerminalError::BackendFailed)?;
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
        let result = record.session.close().await;
        let mut state = self
            .state
            .lock()
            .map_err(|_| TerminalError::StateUnavailable)?;
        state.sessions.remove(session_id);
        result.map_err(|_| TerminalError::BackendFailed)?;
        Ok(true)
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
            let existing = current
                .sessions
                .values()
                .filter(|record| record.owner == owner)
                .count();
            let pending = current.pending_by_owner.get(&owner).copied().unwrap_or(0);
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
    }
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
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    struct StubBackend {
        sessions: Arc<Mutex<Vec<Arc<StubSession>>>>,
    }

    struct StubSession {
        sends: AtomicUsize,
        signals: AtomicUsize,
        closes: AtomicUsize,
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
            });
            self.sessions.lock().unwrap().push(Arc::clone(&session));
            let backend_session: Arc<dyn TerminalBackendSession> = session;
            Box::pin(async move { Ok(backend_session) })
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
            Box::pin(async { Ok(()) })
        }
    }

    fn owner(actor: &str) -> ExecutionScope {
        ExecutionScope::new("account-1", actor, "session-1", "turn-1", "agent-1").unwrap()
    }

    fn service() -> (TerminalService, Arc<Mutex<Vec<Arc<StubSession>>>>) {
        let sessions = Arc::new(Mutex::new(Vec::new()));
        let backend: Arc<dyn TerminalBackend> = Arc::new(StubBackend {
            sessions: Arc::clone(&sessions),
        });
        (TerminalService::new([backend]).unwrap(), sessions)
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
    }
}
