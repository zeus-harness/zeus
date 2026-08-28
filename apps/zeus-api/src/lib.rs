//! HTTP composition for the durable Zeus Alpha slice.

use std::{
    collections::{BTreeMap, HashMap, HashSet},
    convert::Infallible,
    fmt,
    net::{IpAddr, SocketAddr},
    str::FromStr,
    sync::{
        Arc, Mutex as StdMutex,
        atomic::{AtomicU8, Ordering as AtomicOrdering},
    },
    time::{Duration, Instant as StdInstant},
};

use axum::{
    Extension, Json, Router,
    body::Body,
    extract::{
        ConnectInfo, DefaultBodyLimit, Path, Query, Request, State,
        rejection::{JsonRejection, QueryRejection},
    },
    http::{HeaderMap, HeaderValue, Method, StatusCode, Uri, header},
    middleware::{self, Next},
    response::{
        IntoResponse, Response,
        sse::{Event, KeepAlive, Sse},
    },
    routing::{get, post, put},
};
use deployment::{ManifestDiff, ManifestEnvelope};
use execution::{AgentExecutionExplain, AgentRunEpochExplain};
use futures_util::StreamExt;
#[cfg(test)]
use llm::ReplyMessage;
use llm::{
    AGENT_REQUEST_INITIAL_CONTENT_MAX_BYTES, AGENT_REQUEST_MAX_HISTORY_PAIRS_WITH_CONTEXT,
    LocalFallbackProvider, ProviderError, ReplyKind, ReplyOutput, ReplyProvider, ReplyRequest,
    ReplyResponse, ReplyRole, ReplyStreamEvent, ReplyToolCall, ReplyToolDefinition,
    agent_continuation_request, persisted_agent_reply_request, validate_agent_reply_request,
    validate_agent_reply_response_for_request, validate_compaction_response,
    validate_provider_metadata, validate_reply_request, validate_reply_response_for_request,
};
use protocol::{
    ACCOUNT_AUDIT_EVENT_SCHEMA, ACCOUNT_AUDIT_EXPORT_MANIFEST_KIND,
    ACCOUNT_AUDIT_EXPORT_SCHEMA_VERSION,
    AccountAuditArchiveState as AccountAuditArchiveStateResponse, AccountAuditCheckpointResponse,
    AccountAuditEvent, AccountAuditEventPage, AccountAuditExportManifest,
    AccountAuditPolicy as AccountAuditPolicyResponse,
    AccountAuditRollup as AccountAuditRollupResponse,
    AccountAuditState as AccountAuditStateResponse, AccountLifecycleStatus, AccountListResponse,
    AccountMember, AccountMemberPage, AccountRole, AccountStatus, AccountSummary, AccountUser,
    AgentReviewResponse, AgentToolCallStatus, AgentTurnDetail, Approval, ApprovalScope,
    ApprovalStatus, AssistantReplyKind, AssistantReplyProvenance, AuthStatusResponse,
    AuthenticationResponse, BootstrapRequest, COLLECTION_PAGE_DEFAULT_LIMIT,
    CancelAgentTurnRequest, CancelAgentTurnResponse, CreateAccountAuditCheckpointRequest,
    CreateAccountRequest, CreateAccountResponse, CreateMemberRequest, CreateSessionRequest,
    CreateSessionResponse, EVENT_PAGE_DEFAULT_LIMIT, EnqueueSessionFollowupRequest,
    EnqueueSessionFollowupResponse, ForkSessionRequest, ForkSessionResponse, HealthResponse,
    InFlightWorkSummary, LoginRequest, LogoutResponse, MemberSetupRequest,
    MemberSetupTokenResponse, PolicyDecision, ProblemDetails, ReplyProviderCatalogResponse,
    ReplyProviderDescriptor, ResumeSessionRequest, ResumeSessionResponse, ReviewDecision,
    ReviewRequest, ReviewResponse, RotateMemberSetupTokenRequest, RunDetail, SessionDetail,
    SessionEvent, SessionFlushBarrier, SessionFlushBarrierStatus, SessionFollowupListResponse,
    SessionStatus, SessionTurn, StartTurnRequest, SwitchAccountRequest, ThemePreference,
    UpdateAccountAuditPolicyRequest, UpdateAccountReplyProviderRequest, UpdateMemberRequest,
    UpdateMemberResponse, UpdatePreferencesRequest, UserPreferences,
};
#[cfg(test)]
use runtime::ReplyJobSpec;
use runtime::{
    AccountAuditCheckpointCommit, AccountAuditEvent as StoredAccountAuditEvent,
    AccountAuditPolicy as StoredAccountAuditPolicy, AccountAuditRollup as StoredAccountAuditRollup,
    AccountAuditState as StoredAccountAuditState, AccountReplyProviderState,
    AccountReplyProviderUpdateResult, AgentGoalRoundSpec, AgentKnowledgeContextExplain,
    AgentModelCancellationGuard, AgentModelClaimOutcome, AgentModelCompletion,
    AgentModelFailureCommit, AgentModelJob, AgentModelResolution, AgentModelStartOutcome,
    AgentModelSuccessCommit, AgentPromptRevisionPage, AgentPromptState, AgentPromptUpdateResult,
    AgentReviewCommit, AgentSubagentSpawnCommit, AgentToolCall, AgentToolCallSpec,
    AgentToolClaimOutcome, AgentToolCompletion, AgentToolCompletionCommit,
    AgentToolOutcomeUnknownCommit, AgentToolStartOutcome, AgentToolWork, AgentTurnReceiptProbe,
    AgentTurnSpec, AuthPrincipal, AuthSessionCommit, AuthzContext, BootstrapOwnerCommit,
    CreateAccountCommit, DemoStore, EntryRevision, ExecutionScope, KnowledgeCatalogRevisionPage,
    KnowledgeCatalogState, KnowledgeCatalogUpdateResult, MemberSetupCommit, PublishedEvent,
    ReplyClaimOutcome, ReplyFailureCommit, ReplyJob, ReplyOutcomeUnknownCommit, ReplySuccessCommit,
    SessionCompactionClaimOutcome, SessionCompactionFailureCommit, SessionCompactionJob,
    SessionCompactionSuccessCommit, StoreError, StoredAccount, StoredAccountStatus, StoredMember,
    StoredMembershipStatus, StoredPreferences, StoredUser, StoredUserStatus,
    SwitchAuthSessionCommit, TransitionMemberCommit, UpdateAccountAuditPolicyCommit,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tenancy::{
    AccountId, AccountName, AuthSessionId, BootstrapTokenDigest, CsrfToken, CsrfTokenDigest,
    MemberSetupToken, MembershipRole, Password, PasswordAuthenticator, PasswordHashRecord,
    SessionToken, SessionTokenDigest, UserId, Username, hash_password,
};
use tokio::{
    sync::{Mutex, OwnedSemaphorePermit, Semaphore, broadcast},
    time::{Instant, MissedTickBehavior},
};
use zeroize::{Zeroize, Zeroizing};

const DURABLE_LEDGER_POLL_INTERVAL: Duration = Duration::from_secs(2);
const AUTH_JSON_BODY_MAX_BYTES: usize = 8 * 1024;
const COMMAND_JSON_BODY_MAX_BYTES: usize = 512 * 1024;
const KNOWLEDGE_JSON_BODY_MAX_BYTES: usize = 2 * 1024 * 1024 + 4 * 1024;
// JSON permits one Unicode scalar to be represented as a six-byte `\uXXXX`
// escape. Keep the transport cap independent from the decoded 16 KiB prompt
// limit so a valid logical prompt is not rejected solely by its encoding.
const AGENT_PROMPT_JSON_BODY_MAX_BYTES: usize =
    runtime::AGENT_SYSTEM_PROMPT_MAX_BYTES * 6 + 4 * 1024;
const ACCOUNT_AUDIT_EXPORT_MAX_BYTES: usize = 96 * 1024 * 1024;
const PASSWORD_WORKER_LIMIT: usize = 2;
const AUTH_RATE_WINDOW: Duration = Duration::from_secs(60);
const AUTH_RATE_KEY_CAPACITY: usize = 4_096;
const AUTH_RATE_ENTRY_TTL: Duration = Duration::from_secs(15 * 60);
const AUTH_RATE_SWEEP_INTERVAL: Duration = Duration::from_secs(60);
const INVALID_LOGIN_ACCOUNT_KEY: &str = "<invalid-username>";
const SSE_GLOBAL_CONNECTION_LIMIT: usize = 64;
const SSE_ACTOR_CONNECTION_LIMIT: usize = 4;
const SSE_CAPACITY_RETRY_AFTER: Duration = Duration::from_secs(2);
const SESSION_FLUSH_DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);
const SESSION_FLUSH_MAX_TIMEOUT: Duration = Duration::from_secs(30);
const SESSION_FLUSH_POLL_INTERVAL: Duration = Duration::from_millis(100);
const WORKER_ERROR_RETRY_DELAY: Duration = Duration::from_millis(25);
const WORKER_ERROR_RETRY_MAX_DELAY: Duration = Duration::from_secs(1);
const AGENT_COMPLETION_RETRY_MAX_DELAY: Duration = Duration::from_secs(1);
const AGENT_MODEL_WORKER_HOLDER_ID: &str = "zeus-api-agent-model";
const AGENT_TOOL_WORKER_HOLDER_ID: &str = "zeus-api-agent-tool";
const WORKER_IDLE: u8 = 0;
const WORKER_RUNNING: u8 = 1;
const WORKER_PENDING: u8 = 2;
const TRUSTED_PROXY_NETWORK_LIMIT: usize = 32;
const PUBLIC_ORIGIN_MAX_BYTES: usize = 2 * 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IngressPolicy {
    Direct { cookie_secure: bool },
    TrustedProxy(TrustedProxyIngress),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrustedProxyIngress {
    public_origin: String,
    public_authority: String,
    trusted_proxies: Vec<TrustedProxyNetwork>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct TrustedProxyNetwork {
    network: IpAddr,
    prefix: u8,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IngressConfigError(String);

impl fmt::Display for IngressConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for IngressConfigError {}

impl IngressPolicy {
    pub fn direct(cookie_secure: bool) -> Self {
        Self::Direct { cookie_secure }
    }

    pub fn trusted_proxy(
        public_origin: impl Into<String>,
        trusted_proxy_cidrs: impl IntoIterator<Item = impl AsRef<str>>,
    ) -> Result<Self, IngressConfigError> {
        let public_origin = public_origin.into();
        if public_origin.is_empty() || public_origin.len() > PUBLIC_ORIGIN_MAX_BYTES {
            return Err(IngressConfigError(format!(
                "public origin must contain between 1 and {PUBLIC_ORIGIN_MAX_BYTES} bytes"
            )));
        }
        let uri = public_origin
            .parse::<Uri>()
            .map_err(|_| IngressConfigError("public origin is not a valid URI".into()))?;
        if uri.scheme_str() != Some("https") || uri.path() != "/" || uri.query().is_some() {
            return Err(IngressConfigError(
                "public origin must be a canonical HTTPS origin without a path or query".into(),
            ));
        }
        let authority = uri
            .authority()
            .ok_or_else(|| IngressConfigError("public origin has no authority".into()))?;
        if authority.host().is_empty() || authority.as_str().contains('@') {
            return Err(IngressConfigError(
                "public origin must contain a host and cannot contain user information".into(),
            ));
        }
        let port_suffix = authority
            .as_str()
            .strip_prefix(authority.host())
            .ok_or_else(|| IngressConfigError("public origin authority is invalid".into()))?;
        if let Some(raw_port) = port_suffix.strip_prefix(':') {
            let port = raw_port.parse::<u16>().map_err(|_| {
                IngressConfigError(
                    "public origin port must be a canonical unsigned 16-bit value".into(),
                )
            })?;
            if port == 0 || raw_port != port.to_string() {
                return Err(IngressConfigError(
                    "public origin port must be a canonical non-zero unsigned 16-bit value".into(),
                ));
            }
            if port == 443 {
                return Err(IngressConfigError(
                    "public origin must omit the default HTTPS port".into(),
                ));
            }
        } else if !port_suffix.is_empty() {
            return Err(IngressConfigError(
                "public origin authority has an invalid port delimiter".into(),
            ));
        }
        let public_authority = authority.as_str().to_ascii_lowercase();
        let canonical = format!("https://{public_authority}");
        if public_origin != canonical {
            return Err(IngressConfigError(format!(
                "public origin must use the canonical form `{canonical}`"
            )));
        }

        let mut trusted_proxies = Vec::new();
        for cidr in trusted_proxy_cidrs {
            if trusted_proxies.len() == TRUSTED_PROXY_NETWORK_LIMIT {
                return Err(IngressConfigError(format!(
                    "trusted proxy list cannot exceed {TRUSTED_PROXY_NETWORK_LIMIT} networks"
                )));
            }
            let network = TrustedProxyNetwork::from_str(cidr.as_ref())?;
            if trusted_proxies.contains(&network) {
                return Err(IngressConfigError(
                    "trusted proxy networks must be unique".into(),
                ));
            }
            trusted_proxies.push(network);
        }
        if trusted_proxies.is_empty() {
            return Err(IngressConfigError(
                "trusted proxy mode requires at least one proxy CIDR".into(),
            ));
        }
        Ok(Self::TrustedProxy(TrustedProxyIngress {
            public_origin,
            public_authority,
            trusted_proxies,
        }))
    }

    pub fn trusted_proxy_csv(
        public_origin: impl Into<String>,
        trusted_proxy_cidrs: &str,
    ) -> Result<Self, IngressConfigError> {
        if trusted_proxy_cidrs.is_empty() {
            return Err(IngressConfigError(
                "trusted proxy CIDR list cannot be empty".into(),
            ));
        }
        let cidrs = trusted_proxy_cidrs.split(',').collect::<Vec<_>>();
        if cidrs
            .iter()
            .any(|cidr| cidr.is_empty() || cidr.trim() != *cidr)
        {
            return Err(IngressConfigError(
                "trusted proxy CIDRs must be comma-separated without whitespace".into(),
            ));
        }
        Self::trusted_proxy(public_origin, cidrs)
    }

    pub fn cookie_secure(&self) -> bool {
        match self {
            Self::Direct { cookie_secure } => *cookie_secure,
            Self::TrustedProxy(_) => true,
        }
    }

    pub fn mode_name(&self) -> &'static str {
        match self {
            Self::Direct { .. } => "direct",
            Self::TrustedProxy(_) => "trusted-proxy",
        }
    }

    pub fn public_origin(&self) -> Option<&str> {
        match self {
            Self::Direct { .. } => None,
            Self::TrustedProxy(config) => Some(&config.public_origin),
        }
    }
}

impl FromStr for TrustedProxyNetwork {
    type Err = IngressConfigError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let (address, prefix) = value.split_once('/').ok_or_else(|| {
            IngressConfigError("trusted proxy entries must use CIDR notation".into())
        })?;
        let network = address
            .parse::<IpAddr>()
            .map_err(|_| IngressConfigError("trusted proxy CIDR has an invalid address".into()))?;
        let prefix = prefix
            .parse::<u8>()
            .map_err(|_| IngressConfigError("trusted proxy CIDR has an invalid prefix".into()))?;
        let canonical = match network {
            IpAddr::V4(address) if prefix <= 32 => {
                let mask = u32::MAX.checked_shl(u32::from(32 - prefix)).unwrap_or(0);
                u32::from(address) & mask == u32::from(address)
            }
            IpAddr::V6(address) if prefix <= 128 => {
                let mask = u128::MAX.checked_shl(u32::from(128 - prefix)).unwrap_or(0);
                u128::from(address) & mask == u128::from(address)
            }
            _ => false,
        };
        if !canonical {
            return Err(IngressConfigError(
                "trusted proxy CIDR must use a canonical network address and valid prefix".into(),
            ));
        }
        Ok(Self { network, prefix })
    }
}

impl TrustedProxyNetwork {
    fn contains(&self, candidate: IpAddr) -> bool {
        match (self.network, candidate) {
            (IpAddr::V4(network), IpAddr::V4(candidate)) => {
                let mask = u32::MAX
                    .checked_shl(u32::from(32 - self.prefix))
                    .unwrap_or(0);
                u32::from(network) == u32::from(candidate) & mask
            }
            (IpAddr::V6(network), IpAddr::V6(candidate)) => {
                let mask = u128::MAX
                    .checked_shl(u32::from(128 - self.prefix))
                    .unwrap_or(0);
                u128::from(network) == u128::from(candidate) & mask
            }
            _ => false,
        }
    }
}

#[derive(Default)]
struct WorkerWakeState {
    state: AtomicU8,
}

impl WorkerWakeState {
    fn request(&self) -> bool {
        loop {
            match self.state.load(AtomicOrdering::Acquire) {
                WORKER_IDLE => {
                    if self
                        .state
                        .compare_exchange(
                            WORKER_IDLE,
                            WORKER_RUNNING,
                            AtomicOrdering::AcqRel,
                            AtomicOrdering::Acquire,
                        )
                        .is_ok()
                    {
                        return true;
                    }
                }
                WORKER_RUNNING => {
                    if self
                        .state
                        .compare_exchange(
                            WORKER_RUNNING,
                            WORKER_PENDING,
                            AtomicOrdering::AcqRel,
                            AtomicOrdering::Acquire,
                        )
                        .is_ok()
                    {
                        return false;
                    }
                }
                WORKER_PENDING => return false,
                _ => unreachable!("invalid worker wake state"),
            }
        }
    }

    fn complete_cycle(&self) -> bool {
        loop {
            match self.state.load(AtomicOrdering::Acquire) {
                WORKER_RUNNING => {
                    if self
                        .state
                        .compare_exchange(
                            WORKER_RUNNING,
                            WORKER_IDLE,
                            AtomicOrdering::AcqRel,
                            AtomicOrdering::Acquire,
                        )
                        .is_ok()
                    {
                        return false;
                    }
                }
                WORKER_PENDING => {
                    if self
                        .state
                        .compare_exchange(
                            WORKER_PENDING,
                            WORKER_RUNNING,
                            AtomicOrdering::AcqRel,
                            AtomicOrdering::Acquire,
                        )
                        .is_ok()
                    {
                        return true;
                    }
                }
                WORKER_IDLE => return false,
                _ => unreachable!("invalid worker wake state"),
            }
        }
    }
}

async fn retry_agent_durable_progress<T, F, Fut>(
    label: &str,
    mut operation: F,
) -> Result<T, StoreError>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<T, StoreError>>,
{
    let mut attempt = 1_u64;
    let mut retry_delay = WORKER_ERROR_RETRY_DELAY;
    loop {
        match operation().await {
            Ok(completion) => return Ok(completion),
            Err(error) if error.is_retryable_durable_completion_error() => {
                eprintln!(
                    "zeus {label} durable attempt {attempt} failed; retrying without repeating external work: {error}"
                );
                tokio::time::sleep(retry_delay).await;
                retry_delay = std::cmp::min(
                    retry_delay.saturating_mul(2),
                    AGENT_COMPLETION_RETRY_MAX_DELAY,
                );
                attempt = attempt.saturating_add(1);
            }
            Err(error) => return Err(error),
        }
    }
}

/// Retry the exact prepared claim until its durable start result is known.
/// `None` means the claim definitely expired before any external I/O was
/// authorized, so the caller may safely prepare the next generation.
async fn retry_prepared_agent_start<T, F, Fut>(
    label: &str,
    expires_at: &str,
    mut operation: F,
) -> Result<Option<T>, StoreError>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<T, StoreError>>,
{
    let expires_at = chrono::DateTime::parse_from_rfc3339(expires_at).map_err(|_| {
        StoreError::ExecutionInvariant("a prepared Agent claim has an invalid expiry".into())
    })?;
    let mut attempt = 1_u64;
    let mut retry_delay = WORKER_ERROR_RETRY_DELAY;
    loop {
        match operation().await {
            Ok(started) => return Ok(Some(started)),
            Err(StoreError::ConcurrentModification) if chrono::Utc::now() >= expires_at => {
                return Ok(None);
            }
            Err(error) if error.is_retryable_durable_completion_error() => {
                eprintln!(
                    "zeus {label} prepared-start attempt {attempt} failed; retrying the exact claim before external I/O: {error}"
                );
                tokio::time::sleep(retry_delay).await;
                retry_delay = retry_delay
                    .saturating_mul(2)
                    .min(AGENT_COMPLETION_RETRY_MAX_DELAY);
                attempt = attempt.saturating_add(1);
            }
            Err(error) => return Err(error),
        }
    }
}

const LOGIN_RATE_POLICY: RateLimitPolicy = RateLimitPolicy {
    global_limit: 60,
    source_limit: 10,
    account_limit: Some(5),
    window: AUTH_RATE_WINDOW,
    key_capacity: AUTH_RATE_KEY_CAPACITY,
    entry_ttl: AUTH_RATE_ENTRY_TTL,
};

const BOOTSTRAP_RATE_POLICY: RateLimitPolicy = RateLimitPolicy {
    global_limit: 10,
    source_limit: 3,
    account_limit: None,
    window: AUTH_RATE_WINDOW,
    key_capacity: AUTH_RATE_KEY_CAPACITY,
    entry_ttl: AUTH_RATE_ENTRY_TTL,
};

const MEMBER_SETUP_RATE_POLICY: RateLimitPolicy = RateLimitPolicy {
    global_limit: 30,
    source_limit: 5,
    account_limit: None,
    window: AUTH_RATE_WINDOW,
    key_capacity: AUTH_RATE_KEY_CAPACITY,
    entry_ttl: AUTH_RATE_ENTRY_TTL,
};

#[derive(Clone)]
struct ApiState {
    store: DemoStore,
    durable_ledger_poll_interval: Duration,
    broadcast_hints_enabled: bool,
    auth: Option<Arc<AuthConfig>>,
    reply: Option<Arc<ReplyExecutor>>,
    sse_capacity: SseCapacity,
}

struct AuthConfig {
    authenticator: Arc<PasswordAuthenticator>,
    password_workers: Arc<Semaphore>,
    rate_limits: AuthRateLimits,
    ingress: IngressPolicy,
}

trait RateLimitClock: Send + Sync {
    fn now(&self) -> StdInstant;
}

struct SystemRateLimitClock;

impl RateLimitClock for SystemRateLimitClock {
    fn now(&self) -> StdInstant {
        StdInstant::now()
    }
}

#[derive(Clone, Copy)]
struct RateLimitPolicy {
    global_limit: usize,
    source_limit: usize,
    account_limit: Option<usize>,
    window: Duration,
    key_capacity: usize,
    entry_ttl: Duration,
}

struct AuthRateLimits {
    login: AttemptRateLimiter,
    bootstrap: AttemptRateLimiter,
    member_setup: AttemptRateLimiter,
}

impl AuthRateLimits {
    fn new(clock: Arc<dyn RateLimitClock>) -> Self {
        Self::with_policies(clock, LOGIN_RATE_POLICY, BOOTSTRAP_RATE_POLICY)
    }

    fn with_policies(
        clock: Arc<dyn RateLimitClock>,
        login: RateLimitPolicy,
        bootstrap: RateLimitPolicy,
    ) -> Self {
        Self::with_all_policies(clock, login, bootstrap, MEMBER_SETUP_RATE_POLICY)
    }

    fn with_all_policies(
        clock: Arc<dyn RateLimitClock>,
        login: RateLimitPolicy,
        bootstrap: RateLimitPolicy,
        member_setup: RateLimitPolicy,
    ) -> Self {
        Self {
            login: AttemptRateLimiter::new(login, Arc::clone(&clock)),
            bootstrap: AttemptRateLimiter::new(bootstrap, Arc::clone(&clock)),
            member_setup: AttemptRateLimiter::new(member_setup, clock),
        }
    }
}

struct AttemptRateLimiter {
    policy: RateLimitPolicy,
    clock: Arc<dyn RateLimitClock>,
    state: StdMutex<RateLimitState>,
}

#[derive(Default)]
struct RateLimitState {
    global: Option<RateLimitCounter>,
    sources: HashMap<IpAddr, RateLimitCounter>,
    accounts: HashMap<String, RateLimitCounter>,
    next_sweep_at: Option<StdInstant>,
}

#[derive(Clone, Copy)]
struct RateLimitCounter {
    window_started_at: StdInstant,
    count: usize,
    last_seen_at: StdInstant,
}

#[derive(Debug)]
enum RateLimitError {
    Limited(Duration),
    Unavailable,
}

impl AttemptRateLimiter {
    fn new(policy: RateLimitPolicy, clock: Arc<dyn RateLimitClock>) -> Self {
        assert!(
            policy.global_limit > 0,
            "global auth rate limit must be positive"
        );
        assert!(
            policy.source_limit > 0,
            "source auth rate limit must be positive"
        );
        assert!(
            policy.account_limit.is_none_or(|limit| limit > 0),
            "account auth rate limit must be positive"
        );
        assert!(
            !policy.window.is_zero(),
            "auth rate window must be positive"
        );
        assert!(
            policy.key_capacity > 0,
            "auth rate key capacity must be positive"
        );
        assert!(
            !policy.entry_ttl.is_zero(),
            "auth rate entry TTL must be positive"
        );
        Self {
            policy,
            clock,
            state: StdMutex::new(RateLimitState::default()),
        }
    }

    fn charge(&self, source: IpAddr, account: Option<&str>) -> Result<(), RateLimitError> {
        self.charge_at(source, account, self.clock.now())
    }

    fn charge_at(
        &self,
        source: IpAddr,
        account: Option<&str>,
        now: StdInstant,
    ) -> Result<(), RateLimitError> {
        // This is deliberately a fixed-window limiter. The bounded burst at a
        // window boundary is accepted for the local single-instance Alpha; all
        // dimensions are still checked and charged atomically under one lock.
        let mut state = self.state.lock().map_err(|_| RateLimitError::Unavailable)?;
        maybe_prune_rate_limit_keys(&mut state, now, self.policy.entry_ttl);

        let mut retry_after = state.global.as_ref().and_then(|counter| {
            rate_limit_retry_after(counter, now, self.policy.global_limit, self.policy.window)
        });
        retry_after = max_retry_after(
            retry_after,
            state.sources.get(&source).and_then(|counter| {
                rate_limit_retry_after(counter, now, self.policy.source_limit, self.policy.window)
            }),
        );
        if let (Some(account_limit), Some(account)) = (self.policy.account_limit, account) {
            retry_after = max_retry_after(
                retry_after,
                state.accounts.get(account).and_then(|counter| {
                    rate_limit_retry_after(counter, now, account_limit, self.policy.window)
                }),
            );
        }
        if let Some(retry_after) = retry_after {
            return Err(RateLimitError::Limited(retry_after));
        }

        if rate_limit_key_count_after_insert(&state, source, account, self.policy.account_limit)
            > self.policy.key_capacity
        {
            // Fail closed until the next scheduled sweep. Do not scan the
            // complete key map for every attacker-controlled new source once
            // capacity is full; that would turn the memory bound into an O(n)
            // CPU amplification path.
            return Err(RateLimitError::Limited(
                self.policy.entry_ttl.min(AUTH_RATE_SWEEP_INTERVAL),
            ));
        }

        increment_rate_limit_counter(
            state.global.get_or_insert(RateLimitCounter {
                window_started_at: now,
                count: 0,
                last_seen_at: now,
            }),
            now,
            self.policy.window,
        );
        increment_rate_limit_counter(
            state.sources.entry(source).or_insert(RateLimitCounter {
                window_started_at: now,
                count: 0,
                last_seen_at: now,
            }),
            now,
            self.policy.window,
        );
        if let (Some(_), Some(account)) = (self.policy.account_limit, account) {
            increment_rate_limit_counter(
                state
                    .accounts
                    .entry(account.to_owned())
                    .or_insert(RateLimitCounter {
                        window_started_at: now,
                        count: 0,
                        last_seen_at: now,
                    }),
                now,
                self.policy.window,
            );
        }
        Ok(())
    }
}

fn elapsed_since(now: StdInstant, then: StdInstant) -> Duration {
    now.checked_duration_since(then).unwrap_or_default()
}

fn maybe_prune_rate_limit_keys(state: &mut RateLimitState, now: StdInstant, ttl: Duration) {
    if state
        .next_sweep_at
        .is_some_and(|next_sweep_at| now < next_sweep_at)
    {
        return;
    }
    state
        .sources
        .retain(|_, counter| elapsed_since(now, counter.last_seen_at) < ttl);
    state
        .accounts
        .retain(|_, counter| elapsed_since(now, counter.last_seen_at) < ttl);
    state.next_sweep_at = now.checked_add(ttl.min(AUTH_RATE_SWEEP_INTERVAL));
}

fn rate_limit_key_count_after_insert(
    state: &RateLimitState,
    source: IpAddr,
    account: Option<&str>,
    account_limit: Option<usize>,
) -> usize {
    let new_source_key = usize::from(!state.sources.contains_key(&source));
    let new_account_key = usize::from(
        account_limit.is_some()
            && account.is_some_and(|account| !state.accounts.contains_key(account)),
    );
    state.sources.len() + state.accounts.len() + new_source_key + new_account_key
}

fn rate_limit_retry_after(
    counter: &RateLimitCounter,
    now: StdInstant,
    limit: usize,
    window: Duration,
) -> Option<Duration> {
    let elapsed = elapsed_since(now, counter.window_started_at);
    (elapsed < window && counter.count >= limit).then(|| window - elapsed)
}

fn max_retry_after(left: Option<Duration>, right: Option<Duration>) -> Option<Duration> {
    match (left, right) {
        (Some(left), Some(right)) => Some(left.max(right)),
        (Some(value), None) | (None, Some(value)) => Some(value),
        (None, None) => None,
    }
}

fn increment_rate_limit_counter(counter: &mut RateLimitCounter, now: StdInstant, window: Duration) {
    if elapsed_since(now, counter.window_started_at) >= window {
        counter.window_started_at = now;
        counter.count = 0;
    }
    counter.count += 1;
    counter.last_seen_at = now;
}

#[derive(Clone)]
struct SseCapacity {
    inner: Arc<SseCapacityInner>,
}

struct SseCapacityInner {
    global: Arc<Semaphore>,
    actor_counts: StdMutex<HashMap<SseActorKey, usize>>,
    per_actor_limit: usize,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct SseActorKey {
    account_id: AccountId,
    user_id: String,
}

struct SseLease {
    capacity: SseCapacity,
    actor_key: SseActorKey,
    _global_permit: OwnedSemaphorePermit,
}

impl SseCapacity {
    fn new(global_limit: usize, per_actor_limit: usize) -> Self {
        assert!(
            global_limit > 0,
            "global SSE connection limit must be positive"
        );
        assert!(
            per_actor_limit > 0 && per_actor_limit <= global_limit,
            "per-actor SSE limit must be positive and no larger than the global limit"
        );
        Self {
            inner: Arc::new(SseCapacityInner {
                global: Arc::new(Semaphore::new(global_limit)),
                actor_counts: StdMutex::new(HashMap::new()),
                per_actor_limit,
            }),
        }
    }

    fn production() -> Self {
        Self::new(SSE_GLOBAL_CONNECTION_LIMIT, SSE_ACTOR_CONNECTION_LIMIT)
    }

    fn try_acquire(&self, context: &AuthzContext) -> Result<SseLease, RateLimitError> {
        let global_permit = Arc::clone(&self.inner.global)
            .try_acquire_owned()
            .map_err(|_| RateLimitError::Limited(SSE_CAPACITY_RETRY_AFTER))?;
        let mut actor_counts = self
            .inner
            .actor_counts
            .lock()
            .map_err(|_| RateLimitError::Unavailable)?;
        let actor_key = SseActorKey {
            account_id: context.account_id.clone(),
            user_id: context.user_id.clone(),
        };
        let actor_count = actor_counts.entry(actor_key.clone()).or_default();
        if *actor_count >= self.inner.per_actor_limit {
            return Err(RateLimitError::Limited(SSE_CAPACITY_RETRY_AFTER));
        }
        *actor_count += 1;
        drop(actor_counts);
        Ok(SseLease {
            capacity: self.clone(),
            actor_key,
            _global_permit: global_permit,
        })
    }
}

impl Drop for SseLease {
    fn drop(&mut self) {
        let mut actor_counts = self
            .capacity
            .inner
            .actor_counts
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(actor_count) = actor_counts.get_mut(&self.actor_key) {
            *actor_count = actor_count.saturating_sub(1);
            if *actor_count == 0 {
                actor_counts.remove(&self.actor_key);
            }
        }
    }
}

struct ReplyExecutor {
    providers: ProviderRegistry,
    reply_drain: Mutex<()>,
    reply_worker_wake: WorkerWakeState,
    agent_model_drain: Mutex<()>,
    agent_model_worker_wake: WorkerWakeState,
    compaction_drain: Mutex<()>,
    compaction_worker_wake: WorkerWakeState,
    agent_tool_drain: Mutex<()>,
    agent_tool_worker_wake: WorkerWakeState,
    followup_drain: Mutex<()>,
    followup_worker_wake: WorkerWakeState,
    goal_round_drain: Mutex<()>,
    goal_round_worker_wake: WorkerWakeState,
}

impl ReplyExecutor {
    fn new(provider: Arc<dyn ReplyProvider>) -> Self {
        Self::with_registry(ProviderRegistry::single(provider))
    }

    fn with_registry(providers: ProviderRegistry) -> Self {
        Self {
            providers,
            reply_drain: Mutex::new(()),
            reply_worker_wake: WorkerWakeState::default(),
            agent_model_drain: Mutex::new(()),
            agent_model_worker_wake: WorkerWakeState::default(),
            compaction_drain: Mutex::new(()),
            compaction_worker_wake: WorkerWakeState::default(),
            agent_tool_drain: Mutex::new(()),
            agent_tool_worker_wake: WorkerWakeState::default(),
            followup_drain: Mutex::new(()),
            followup_worker_wake: WorkerWakeState::default(),
            goal_round_drain: Mutex::new(()),
            goal_round_worker_wake: WorkerWakeState::default(),
        }
    }
}

#[derive(Clone)]
struct ProviderRegistry {
    default_provider_id: String,
    providers: BTreeMap<String, Arc<dyn ReplyProvider>>,
}

impl ProviderRegistry {
    fn single(provider: Arc<dyn ReplyProvider>) -> Self {
        let default_provider_id = provider.metadata().provider_id.clone();
        let mut providers = BTreeMap::new();
        providers.insert(default_provider_id.clone(), provider);
        Self {
            default_provider_id,
            providers,
        }
    }

    fn build(
        default: Arc<dyn ReplyProvider>,
        additional: Vec<Arc<dyn ReplyProvider>>,
    ) -> Result<Self, ProviderRegistryError> {
        let default_provider_id = default.metadata().provider_id.clone();
        let mut providers = BTreeMap::new();
        providers.insert(default_provider_id.clone(), default);
        for provider in additional {
            let provider_id = provider.metadata().provider_id.clone();
            if providers.insert(provider_id.clone(), provider).is_some() {
                return Err(ProviderRegistryError::DuplicateProviderId(provider_id));
            }
        }
        Ok(Self {
            default_provider_id,
            providers,
        })
    }

    fn default_provider(&self) -> &Arc<dyn ReplyProvider> {
        self.providers
            .get(&self.default_provider_id)
            .expect("the provider registry always owns its default")
    }

    fn get(&self, provider_id: &str) -> Option<&Arc<dyn ReplyProvider>> {
        self.providers.get(provider_id)
    }

    fn default_state(&self, account_id: AccountId) -> AccountReplyProviderState {
        let metadata = self.default_provider().metadata();
        AccountReplyProviderState {
            account_id,
            revision: 0,
            provider_id: metadata.provider_id.clone(),
            model: metadata.model.clone(),
            reply_kind: assistant_reply_kind(metadata.reply_kind),
            updated_by_user_id: None,
            updated_by_membership_revision: None,
            updated_at: None,
        }
    }

    fn descriptors(&self) -> Vec<ReplyProviderDescriptor> {
        self.providers
            .values()
            .map(|provider| {
                let metadata = provider.metadata();
                ReplyProviderDescriptor {
                    provider_id: metadata.provider_id.clone(),
                    model: metadata.model.clone(),
                    reply_kind: assistant_reply_kind(metadata.reply_kind),
                }
            })
            .collect()
    }
}

#[derive(Debug)]
pub enum ProviderRegistryError {
    DuplicateProviderId(String),
}

impl fmt::Display for ProviderRegistryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DuplicateProviderId(provider_id) => {
                write!(formatter, "duplicate reply provider ID `{provider_id}`")
            }
        }
    }
}

impl std::error::Error for ProviderRegistryError {}

#[derive(Clone)]
struct CurrentAuth {
    principal: AuthPrincipal,
    session_token_hash: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct EffectiveClientIp(IpAddr);

#[cfg(test)]
#[derive(Clone)]
struct TestRequestAuth {
    authz: AuthzContext,
    cookie_header: HeaderValue,
    csrf_token: HeaderValue,
}

#[derive(Debug, Default, Deserialize)]
struct EventsQuery {
    after: Option<u64>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct AgentOutputQuery {
    after: Option<u64>,
    limit: Option<usize>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct SessionFlushQuery {
    timeout_ms: Option<u64>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct SessionListQuery {
    cursor: Option<String>,
    limit: Option<usize>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct SessionForkListQuery {
    cursor: Option<String>,
    limit: Option<usize>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct MemberListQuery {
    cursor: Option<String>,
    limit: Option<usize>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct AuditListQuery {
    cursor: Option<String>,
    limit: Option<usize>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReplaceKnowledgeCatalogRequest {
    expected_revision: u64,
    entries: Vec<EntryRevision>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReplaceAgentPromptRequest {
    expected_revision: u64,
    content: String,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct AgentPromptRevisionListQuery {
    before_revision: Option<u64>,
    limit: Option<usize>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct KnowledgeCatalogRevisionListQuery {
    before_revision: Option<u64>,
    limit: Option<usize>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct SessionDetailQuery {
    run_ids_before: Option<String>,
    run_ids_limit: Option<usize>,
    turns_before: Option<String>,
    turns_limit: Option<usize>,
    events_before: Option<String>,
    events_limit: Option<usize>,
}

#[derive(Debug, Serialize, Deserialize)]
struct AgentDeploymentExplainResponse {
    agent: AgentTurnDetail,
    persisted_manifest: Option<ManifestEnvelope>,
    current_manifest: ManifestEnvelope,
    legacy_unbound: bool,
    matches_current: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    diff: Option<ManifestDiff>,
}

#[derive(Debug, Serialize)]
struct AgentKnowledgeExplainResponse {
    agent: AgentTurnDetail,
    legacy_unbound: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    context: Option<AgentKnowledgeContextExplain>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RunDetailQuery {
    events_before: Option<String>,
    events_limit: Option<usize>,
}

pub fn authenticated_app(
    store: DemoStore,
    cookie_secure: bool,
) -> Result<Router, tenancy::CredentialError> {
    authenticated_app_with_provider(store, cookie_secure, Arc::new(LocalFallbackProvider::new()))
}

pub fn authenticated_app_with_provider(
    store: DemoStore,
    cookie_secure: bool,
    provider: Arc<dyn ReplyProvider>,
) -> Result<Router, tenancy::CredentialError> {
    authenticated_app_with_provider_and_ingress(
        store,
        IngressPolicy::direct(cookie_secure),
        provider,
    )
}

pub fn authenticated_app_with_provider_and_ingress(
    store: DemoStore,
    ingress: IngressPolicy,
    provider: Arc<dyn ReplyProvider>,
) -> Result<Router, tenancy::CredentialError> {
    let auth = auth_config_with_clock(ingress, Arc::new(SystemRateLimitClock))?;
    let reply = Arc::new(ReplyExecutor::new(provider));
    Ok(authenticated_app_with_auth_and_executor(store, auth, reply))
}

/// Build the authenticated API with a bounded startup-owned provider registry.
/// The first provider is the implicit revision-zero default; additional
/// providers can be selected by account owners but cannot be configured over
/// HTTP.
pub fn authenticated_app_with_provider_registry_and_ingress(
    store: DemoStore,
    ingress: IngressPolicy,
    default_provider: Arc<dyn ReplyProvider>,
    additional_providers: Vec<Arc<dyn ReplyProvider>>,
) -> Result<Router, AuthenticatedAppBuildError> {
    let auth = auth_config_with_clock(ingress, Arc::new(SystemRateLimitClock))?;
    let registry = ProviderRegistry::build(default_provider, additional_providers)?;
    let reply = Arc::new(ReplyExecutor::with_registry(registry));
    Ok(authenticated_app_with_auth_and_executor(store, auth, reply))
}

#[derive(Debug)]
pub enum AuthenticatedAppBuildError {
    Credential(tenancy::CredentialError),
    ProviderRegistry(ProviderRegistryError),
}

impl fmt::Display for AuthenticatedAppBuildError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Credential(error) => error.fmt(formatter),
            Self::ProviderRegistry(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for AuthenticatedAppBuildError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Credential(error) => Some(error),
            Self::ProviderRegistry(error) => Some(error),
        }
    }
}

impl From<tenancy::CredentialError> for AuthenticatedAppBuildError {
    fn from(error: tenancy::CredentialError) -> Self {
        Self::Credential(error)
    }
}

impl From<ProviderRegistryError> for AuthenticatedAppBuildError {
    fn from(error: ProviderRegistryError) -> Self {
        Self::ProviderRegistry(error)
    }
}

fn authenticated_app_with_auth_and_executor(
    store: DemoStore,
    auth: Arc<AuthConfig>,
    reply: Arc<ReplyExecutor>,
) -> Router {
    let state = ApiState {
        store,
        durable_ledger_poll_interval: DURABLE_LEDGER_POLL_INTERVAL,
        broadcast_hints_enabled: true,
        auth: Some(auth),
        reply: Some(reply),
        sse_capacity: SseCapacity::production(),
    };
    build_authenticated_app(state)
}

fn auth_config_with_clock(
    ingress: IngressPolicy,
    clock: Arc<dyn RateLimitClock>,
) -> Result<Arc<AuthConfig>, tenancy::CredentialError> {
    Ok(Arc::new(AuthConfig {
        authenticator: Arc::new(PasswordAuthenticator::new()?),
        password_workers: Arc::new(Semaphore::new(PASSWORD_WORKER_LIMIT)),
        rate_limits: AuthRateLimits::new(clock),
        ingress,
    }))
}

fn build_authenticated_app(state: ApiState) -> Router {
    assert!(
        !state.durable_ledger_poll_interval.is_zero(),
        "the durable ledger poll interval must be positive"
    );
    assert!(
        state.auth.is_some() && state.reply.is_some(),
        "the production router requires authentication and a reply executor"
    );

    let protected = Router::new()
        .route("/api/v1/overview", get(overview))
        .route("/api/v1/sessions", get(list_sessions).post(create_session))
        .route("/api/v1/sessions/{id}", get(session_detail))
        .route(
            "/api/v1/sessions/{id}/forks",
            get(list_session_forks).post(fork_session),
        )
        .route("/api/v1/sessions/{id}/resume", post(resume_session))
        .route("/api/v1/sessions/{id}/flush", post(flush_session))
        .route(
            "/api/v1/sessions/{id}/followups",
            get(list_session_followups).post(enqueue_session_followup),
        )
        .route("/api/v1/sessions/{id}/turns", post(start_turn))
        .route("/api/v1/sessions/{id}/turns/{turn_id}", get(session_turn))
        .route(
            "/api/v1/sessions/{id}/turns/{turn_id}/agent",
            get(agent_turn_detail),
        )
        .route(
            "/api/v1/sessions/{id}/turns/{turn_id}/output",
            get(agent_output_chunks),
        )
        .route(
            "/api/v1/sessions/{id}/turns/{turn_id}/output/events",
            get(agent_output_events),
        )
        .route(
            "/api/v1/sessions/{id}/turns/{turn_id}/agent/cancel",
            put(cancel_agent_turn),
        )
        .route(
            "/api/v1/sessions/{id}/turns/{turn_id}/agent/explain",
            get(agent_deployment_explain),
        )
        .route(
            "/api/v1/sessions/{id}/turns/{turn_id}/agent/deployment/explain",
            get(agent_deployment_explain),
        )
        .route(
            "/api/v1/sessions/{id}/turns/{turn_id}/agent/execution/explain",
            get(agent_execution_explain),
        )
        .route(
            "/api/v1/sessions/{id}/turns/{turn_id}/agent/knowledge/explain",
            get(agent_knowledge_explain),
        )
        .route(
            "/api/v1/sessions/{id}/turns/{turn_id}/agent/execution/epochs/{step}",
            get(agent_run_epoch_explain),
        )
        .route(
            "/api/v1/sessions/{id}/turns/{turn_id}/approvals/{call_id}/decision",
            post(agent_review_decision),
        )
        .route("/api/v1/sessions/{id}/events", get(session_events))
        .route("/api/v1/runs/{id}", get(run_detail))
        .route(
            "/api/v1/runs/{id}/approvals/{approval_id}/decision",
            post(review_decision),
        )
        .route("/api/v1/runs/{id}/events", get(run_events))
        .route("/api/v1/auth/logout", post(logout))
        .route(
            "/api/v1/me/settings",
            get(get_preferences).patch(patch_preferences),
        )
        .route("/api/v1/providers", get(get_reply_provider_catalog))
        .route_layer(middleware::from_fn_with_state(state.clone(), require_auth))
        .layer(DefaultBodyLimit::max(COMMAND_JSON_BODY_MAX_BYTES));

    let account_control = Router::new()
        .route("/api/v1/accounts", get(list_accounts).post(create_account))
        .route("/api/v1/auth/switch-account", post(switch_account))
        .route_layer(middleware::from_fn_with_state(state.clone(), require_auth))
        .layer(DefaultBodyLimit::max(AUTH_JSON_BODY_MAX_BYTES));

    let account_admin = Router::new()
        .route("/api/v1/members", get(list_members).post(create_member))
        .route(
            "/api/v1/members/{user_id}",
            axum::routing::patch(update_member),
        )
        .route(
            "/api/v1/members/{user_id}/setup-token",
            post(rotate_member_setup_token),
        )
        .route("/api/v1/audit/events", get(list_account_audit_events))
        .route("/api/v1/audit/export", get(export_account_audit_events))
        .route(
            "/api/v1/audit/policy",
            get(get_account_audit_policy).put(update_account_audit_policy),
        )
        .route(
            "/api/v1/audit/archive/checkpoint",
            post(checkpoint_account_audit_archive),
        )
        .route_layer(middleware::from_fn(
            reject_unsupported_account_admin_idempotency,
        ))
        .route_layer(middleware::from_fn(require_account_owner))
        .route_layer(middleware::from_fn_with_state(state.clone(), require_auth))
        .layer(DefaultBodyLimit::max(AUTH_JSON_BODY_MAX_BYTES));

    let knowledge_admin = Router::new()
        .route(
            "/api/v1/knowledge/catalog",
            get(get_knowledge_catalog).put(replace_knowledge_catalog),
        )
        .route(
            "/api/v1/knowledge/catalog/revisions",
            get(list_knowledge_catalog_revisions),
        )
        .route(
            "/api/v1/knowledge/catalog/revisions/{revision}",
            get(get_knowledge_catalog_revision),
        )
        .route_layer(middleware::from_fn(require_account_owner))
        .route_layer(middleware::from_fn_with_state(state.clone(), require_auth))
        .layer(DefaultBodyLimit::max(KNOWLEDGE_JSON_BODY_MAX_BYTES));

    let agent_prompt_admin = Router::new()
        .route(
            "/api/v1/agent/prompt",
            get(get_agent_prompt).put(replace_agent_prompt),
        )
        .route(
            "/api/v1/agent/prompt/revisions",
            get(list_agent_prompt_revisions),
        )
        .route(
            "/api/v1/agent/prompt/revisions/{revision}",
            get(get_agent_prompt_revision),
        )
        .route_layer(middleware::from_fn(require_account_owner))
        .route_layer(middleware::from_fn_with_state(state.clone(), require_auth))
        .layer(DefaultBodyLimit::max(AGENT_PROMPT_JSON_BODY_MAX_BYTES));

    let reply_provider_admin = Router::new()
        .route(
            "/api/v1/account/reply-provider",
            get(get_account_reply_provider).put(update_account_reply_provider),
        )
        .route_layer(middleware::from_fn(require_account_owner))
        .route_layer(middleware::from_fn_with_state(state.clone(), require_auth))
        .layer(DefaultBodyLimit::max(AUTH_JSON_BODY_MAX_BYTES));

    let public = Router::new()
        .route("/health/live", get(liveness))
        .route("/health/ready", get(readiness))
        .route("/api/v1/auth/status", get(auth_status))
        .route("/api/v1/auth/bootstrap", post(bootstrap))
        .route("/api/v1/auth/login", post(login))
        .route("/api/v1/auth/member-setup", post(member_setup))
        .route("/api/auth/member-setup", post(member_setup))
        .layer(DefaultBodyLimit::max(AUTH_JSON_BODY_MAX_BYTES));

    let router = public
        .merge(protected)
        .merge(account_control)
        .merge(account_admin)
        .merge(knowledge_admin)
        .merge(agent_prompt_admin)
        .merge(reply_provider_admin)
        .fallback(not_found)
        .layer(middleware::from_fn_with_state(
            state.clone(),
            enforce_ingress,
        ))
        .with_state(state.clone());
    #[cfg(test)]
    let router = router.layer(middleware::from_fn(inject_test_connect_info));
    kick_reply_worker(&state);
    kick_agent_model_worker(&state);
    kick_compaction_worker(&state);
    kick_agent_tool_worker(&state);
    kick_followup_worker(&state);
    router
}

#[cfg(test)]
async fn inject_test_connect_info(mut request: Request, next: Next) -> Response {
    if request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .is_none()
    {
        let peer = request
            .headers_mut()
            .remove("x-zeus-test-peer")
            .and_then(|value| value.to_str().ok()?.parse::<SocketAddr>().ok())
            .unwrap_or_else(|| {
                "127.0.0.1:41000"
                    .parse::<SocketAddr>()
                    .expect("test peer is valid")
            });
        request.extensions_mut().insert(ConnectInfo(peer));
    }
    next.run(request).await
}

#[cfg(test)]
async fn app(store: DemoStore) -> Router {
    app_with_auth(store).await.0
}

#[cfg(test)]
async fn app_with_auth(store: DemoStore) -> (Router, TestRequestAuth) {
    app_with_event_feed_options_and_auth(store, DURABLE_LEDGER_POLL_INTERVAL, true).await
}

#[cfg(test)]
async fn app_with_event_feed_options(
    store: DemoStore,
    durable_ledger_poll_interval: Duration,
    broadcast_hints_enabled: bool,
) -> Router {
    app_with_event_feed_options_and_auth(
        store,
        durable_ledger_poll_interval,
        broadcast_hints_enabled,
    )
    .await
    .0
}

#[cfg(test)]
async fn app_with_event_feed_options_and_auth(
    store: DemoStore,
    durable_ledger_poll_interval: Duration,
    broadcast_hints_enabled: bool,
) -> (Router, TestRequestAuth) {
    assert!(
        !durable_ledger_poll_interval.is_zero(),
        "the durable ledger poll interval must be positive"
    );
    let request_auth = configure_test_actor(&store).await;
    let auth = auth_config_with_clock(IngressPolicy::direct(false), Arc::new(SystemRateLimitClock))
        .unwrap();
    let state = ApiState {
        store,
        durable_ledger_poll_interval,
        broadcast_hints_enabled,
        auth: Some(auth),
        reply: None,
        sse_capacity: SseCapacity::production(),
    };
    (build_test_app(state, request_auth.clone()), request_auth)
}

#[cfg(test)]
fn build_test_app(state: ApiState, request_auth: TestRequestAuth) -> Router {
    let protected = Router::new()
        .route("/api/v1/overview", get(overview))
        .route("/api/v1/sessions", get(list_sessions).post(create_session))
        .route("/api/v1/sessions/{id}", get(session_detail))
        .route("/api/v1/sessions/{id}/resume", post(resume_session))
        .route("/api/v1/sessions/{id}/flush", post(flush_session))
        .route(
            "/api/v1/sessions/{id}/followups",
            get(list_session_followups).post(enqueue_session_followup),
        )
        .route("/api/v1/sessions/{id}/turns", post(test_start_turn))
        .route("/api/v1/sessions/{id}/turns/{turn_id}", get(session_turn))
        .route(
            "/api/v1/sessions/{id}/turns/{turn_id}/agent",
            get(agent_turn_detail),
        )
        .route(
            "/api/v1/sessions/{id}/turns/{turn_id}/output",
            get(agent_output_chunks),
        )
        .route(
            "/api/v1/sessions/{id}/turns/{turn_id}/output/events",
            get(agent_output_events),
        )
        .route(
            "/api/v1/sessions/{id}/turns/{turn_id}/agent/cancel",
            put(cancel_agent_turn),
        )
        .route(
            "/api/v1/sessions/{id}/turns/{turn_id}/agent/explain",
            get(agent_deployment_explain),
        )
        .route(
            "/api/v1/sessions/{id}/turns/{turn_id}/agent/deployment/explain",
            get(agent_deployment_explain),
        )
        .route(
            "/api/v1/sessions/{id}/turns/{turn_id}/agent/execution/explain",
            get(agent_execution_explain),
        )
        .route(
            "/api/v1/sessions/{id}/turns/{turn_id}/agent/execution/epochs/{step}",
            get(agent_run_epoch_explain),
        )
        .route(
            "/api/v1/sessions/{id}/turns/{turn_id}/approvals/{call_id}/decision",
            post(agent_review_decision),
        )
        .route(
            "/api/v1/sessions/{id}/turns/{turn_id}/flush",
            post(test_flush_turn),
        )
        .route("/api/v1/sessions/{id}/events", get(session_events))
        .route("/api/v1/runs/{id}", get(run_detail))
        .route(
            "/api/v1/runs/{id}/approvals/{approval_id}/decision",
            post(review_decision),
        )
        .route("/api/v1/runs/{id}/events", get(run_events))
        .route_layer(middleware::from_fn_with_state(state.clone(), require_auth))
        .layer(DefaultBodyLimit::max(COMMAND_JSON_BODY_MAX_BYTES));
    let public = Router::new()
        .route("/health/live", get(liveness))
        .route("/health/ready", get(readiness));
    public
        .merge(protected)
        .fallback(not_found)
        .with_state(state)
        .layer(middleware::from_fn_with_state(
            request_auth,
            inject_test_auth,
        ))
}

#[cfg(test)]
async fn configure_test_actor(store: &DemoStore) -> TestRequestAuth {
    let bootstrap_token_hash = "a".repeat(64);
    let auth_session_id = AuthSessionId::generate().unwrap();
    let session_token = SessionToken::generate().unwrap();
    let csrf_token = CsrfToken::generate().unwrap();
    let expires_at = (chrono::Utc::now() + chrono::Duration::hours(1))
        .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    store
        .replace_bootstrap_token(&bootstrap_token_hash, &expires_at)
        .await
        .expect("the test bootstrap token should persist");
    store
        .bootstrap_owner(BootstrapOwnerCommit {
            bootstrap_token_hash,
            user_id: "user-test-owner".into(),
            username: "test-owner".into(),
            password_hash: "$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$ZGlnaWVzdA".into(),
            auth_session_id: auth_session_id.clone(),
            session_token_hash: session_token.digest().to_persistence(),
            csrf_hash: csrf_token.digest().to_persistence(),
            session_expires_at: expires_at,
        })
        .await
        .expect("the test owner should claim the seeded resources");
    TestRequestAuth {
        authz: AuthzContext {
            account_id: AccountId::local(),
            user_id: "user-test-owner".into(),
            membership_role: MembershipRole::Owner,
            membership_revision: tenancy::MembershipRevision::new(1).unwrap(),
            auth_session_id,
        },
        cookie_header: HeaderValue::from_str(&format!(
            "{SESSION_COOKIE}={}; {CSRF_COOKIE}={}",
            session_token.expose_secret(),
            csrf_token.expose_secret()
        ))
        .unwrap(),
        csrf_token: HeaderValue::from_str(csrf_token.expose_secret()).unwrap(),
    }
}

#[cfg(test)]
async fn inject_test_auth(
    State(auth): State<TestRequestAuth>,
    mut request: Request,
    next: Next,
) -> Response {
    request
        .headers_mut()
        .insert(header::HOST, HeaderValue::from_static("zeus.test"));
    request
        .headers_mut()
        .insert(header::ORIGIN, HeaderValue::from_static("http://zeus.test"));
    request
        .headers_mut()
        .insert(header::COOKIE, auth.cookie_header);
    request.headers_mut().insert(CSRF_HEADER, auth.csrf_token);
    next.run(request).await
}

async fn liveness() -> Json<HealthResponse> {
    Json(HealthResponse { status: "ok" })
}

async fn readiness(State(state): State<ApiState>) -> Result<Json<HealthResponse>, ApiError> {
    match state.store.readiness().await {
        Ok(()) => {}
        Err(StoreError::PhysicalStorageExhausted) => {
            return Err(ApiError::unavailable_message(
                "The runtime cannot safely accept new durable work at the current disk watermark",
            ));
        }
        Err(error) => return Err(error.into()),
    }
    Ok(Json(HealthResponse { status: "ready" }))
}

async fn auth_status(
    State(state): State<ApiState>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let configured = state.store.has_users().await?;
    let principal = if configured {
        authenticate_headers(&state, &headers).await?
    } else {
        None
    };
    let (account_id, user, preferences) = if let Some(principal) = principal {
        let preferences = state.store.preferences(&principal.authz).await?;
        (
            Some(principal.authz.account_id.as_str().to_owned()),
            Some(account_user(
                &principal.user,
                principal.authz.membership_role,
            )),
            Some(user_preferences(&preferences)?),
        )
    } else {
        (None, None, None)
    };
    let mut response = Json(AuthStatusResponse {
        configured,
        authenticated: user.is_some(),
        account_id,
        user,
        preferences,
    })
    .into_response();
    no_store(response.headers_mut());
    Ok(response)
}

async fn bootstrap(
    State(state): State<ApiState>,
    Extension(source): Extension<EffectiveClientIp>,
    headers: HeaderMap,
    payload: Result<Json<BootstrapRequest>, JsonRejection>,
) -> Result<Response, ApiError> {
    enforce_same_origin(&headers, &auth_config(&state)?.ingress)?;
    if state.store.has_users().await? {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "account_already_configured",
            "Owner already configured",
            "This Zeus instance already has an owner account",
        ));
    }
    let Json(request) = payload.map_err(ApiError::invalid_json)?;
    let mut bootstrap_token = Zeroizing::new(request.bootstrap_token);
    let mut presented_password = Zeroizing::new(request.password);
    let auth = auth_config(&state)?;
    charge_auth_rate_limit(
        &auth.rate_limits.bootstrap,
        source.0,
        None,
        "bootstrap_rate_limited",
        "Owner setup temporarily limited",
    )?;
    let bootstrap_digest = BootstrapTokenDigest::from_presented(bootstrap_token.as_str());
    bootstrap_token.zeroize();
    let bootstrap_hash = bootstrap_digest
        .map_err(|_| ApiError::invalid_bootstrap())?
        .to_persistence();
    let password_value = presented_password.as_str().to_owned();
    presented_password.zeroize();
    let password = Password::new(password_value)
        .map_err(|error| ApiError::bad_request("invalid_password", error.to_string()))?;
    let username = Username::parse(request.username)
        .map_err(|error| ApiError::bad_request("invalid_username", error.to_string()))?;
    let permit = auth
        .password_workers
        .clone()
        .try_acquire_owned()
        .map_err(|_| ApiError::auth_unavailable("password workers are busy"))?;
    let password_hash = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        hash_password(&password)
    })
    .await
    .map_err(|error| ApiError::auth_unavailable(&error))?
    .map_err(|error| ApiError::auth_unavailable(&error))?;

    let user_id = UserId::generate().map_err(|error| ApiError::auth_unavailable(&error))?;
    let (auth_session_id, session_token, csrf_token, expires_at) = fresh_auth_tokens()?;
    let (user, preferences) = state
        .store
        .bootstrap_owner(BootstrapOwnerCommit {
            bootstrap_token_hash: bootstrap_hash,
            user_id: user_id.as_str().to_owned(),
            username: username.as_str().to_owned(),
            password_hash: password_hash.as_phc().to_owned(),
            auth_session_id,
            session_token_hash: session_token.digest().to_persistence(),
            csrf_hash: csrf_token.digest().to_persistence(),
            session_expires_at: expires_at.clone(),
        })
        .await
        .map_err(|error| match error {
            StoreError::InvalidBootstrapToken => ApiError::invalid_bootstrap(),
            other => other.into(),
        })?;

    authentication_response(
        &state,
        &session_token,
        &csrf_token,
        &expires_at,
        AuthenticationSubject {
            account_id: AccountId::local(),
            user,
            membership_role: MembershipRole::Owner,
            preferences,
        },
    )
}

async fn login(
    State(state): State<ApiState>,
    Extension(source): Extension<EffectiveClientIp>,
    headers: HeaderMap,
    payload: Result<Json<LoginRequest>, JsonRejection>,
) -> Result<Response, ApiError> {
    enforce_same_origin(&headers, &auth_config(&state)?.ingress)?;
    if !state.store.has_users().await? {
        return Err(ApiError::new(
            StatusCode::PRECONDITION_REQUIRED,
            "setup_required",
            "Owner setup required",
            "Bootstrap the local owner account before signing in",
        ));
    }
    let Json(request) = payload.map_err(ApiError::invalid_json)?;
    let password = Zeroizing::new(request.password);
    let normalized_username = Username::parse(&request.username).ok();
    let requested_account_id = request
        .account_id
        .as_deref()
        .map(AccountId::parse)
        .unwrap_or_else(|| Ok(AccountId::local()))
        .ok();
    let account_key = normalized_username
        .as_ref()
        .map(Username::as_str)
        .unwrap_or(INVALID_LOGIN_ACCOUNT_KEY);
    let auth = auth_config(&state)?;
    charge_auth_rate_limit(
        &auth.rate_limits.login,
        source.0,
        Some(account_key),
        "login_rate_limited",
        "Sign-in temporarily limited",
    )?;
    let credential =
        if let (Some(username), Some(account_id)) = (&normalized_username, &requested_account_id) {
            state
                .store
                .credential_for_username_in_account(username.as_str(), account_id)
                .await?
        } else {
            None
        };
    let record = credential
        .as_ref()
        .map(|credential| PasswordHashRecord::parse(&credential.password_hash))
        .transpose()
        .map_err(|error| ApiError::auth_unavailable(&error))?;
    let authenticator = Arc::clone(&auth.authenticator);
    let permit = auth
        .password_workers
        .clone()
        .try_acquire_owned()
        .map_err(|_| ApiError::auth_unavailable("password workers are busy"))?;
    let verified = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        authenticator.verify(record.as_ref(), password.as_str())
    })
    .await
    .map_err(|error| ApiError::auth_unavailable(&error))?
    .map_err(|error| ApiError::auth_unavailable(&error))?;
    let credential = credential
        .filter(|credential| verified && credential.user.status == StoredUserStatus::Active);
    let Some(credential) = credential else {
        return Err(ApiError::invalid_login());
    };

    let (auth_session_id, session_token, csrf_token, expires_at) = fresh_auth_tokens()?;
    let context = AuthzContext {
        account_id: credential.account_id.clone(),
        user_id: credential.user.id.clone(),
        membership_role: credential.membership_role,
        membership_revision: credential.membership_revision,
        auth_session_id,
    };
    state
        .store
        .create_auth_session(AuthSessionCommit {
            authz: context.clone(),
            session_token_hash: session_token.digest().to_persistence(),
            csrf_hash: csrf_token.digest().to_persistence(),
            expires_at: expires_at.clone(),
        })
        .await
        .map_err(|error| match error {
            StoreError::UserNotFound(_)
            | StoreError::UserDisabled(_)
            | StoreError::AuthSessionNotFound
            | StoreError::PermissionDenied => ApiError::invalid_login(),
            other => other.into(),
        })?;
    let preferences = state.store.preferences(&context).await?;
    authentication_response(
        &state,
        &session_token,
        &csrf_token,
        &expires_at,
        AuthenticationSubject {
            account_id: context.account_id,
            user: credential.user,
            membership_role: context.membership_role,
            preferences,
        },
    )
}

async fn list_accounts(
    State(state): State<ApiState>,
    Extension(current): Extension<CurrentAuth>,
) -> Result<Response, ApiError> {
    let accounts = state
        .store
        .accounts_for_user(&current.principal.authz)
        .await?
        .into_iter()
        .map(account_summary)
        .collect();
    let mut response = Json(AccountListResponse {
        current_account_id: current.principal.authz.account_id.as_str().to_owned(),
        accounts,
    })
    .into_response();
    no_store(response.headers_mut());
    Ok(response)
}

async fn create_account(
    State(state): State<ApiState>,
    Extension(current): Extension<CurrentAuth>,
    headers: HeaderMap,
    payload: Result<Json<CreateAccountRequest>, JsonRejection>,
) -> Result<Response, ApiError> {
    let idempotency_key = required_idempotency_key(&headers)?;
    let Json(request) = payload.map_err(ApiError::invalid_json)?;
    let name = AccountName::parse(request.name)
        .map_err(|error| ApiError::bad_request("invalid_account_name", error.to_string()))?;
    let account_id = AccountId::for_creation(&current.principal.user.id, &idempotency_key);
    let result = state
        .store
        .create_account(
            &current.principal.authz,
            CreateAccountCommit {
                account_id,
                name: name.as_str().to_owned(),
            },
        )
        .await?;
    let status = if result.replayed {
        StatusCode::OK
    } else {
        StatusCode::CREATED
    };
    let mut response = (
        status,
        Json(CreateAccountResponse {
            account: account_summary(result.account),
            replayed: result.replayed,
        }),
    )
        .into_response();
    no_store(response.headers_mut());
    Ok(response)
}

async fn switch_account(
    State(state): State<ApiState>,
    Extension(current): Extension<CurrentAuth>,
    headers: HeaderMap,
    payload: Result<Json<SwitchAccountRequest>, JsonRejection>,
) -> Result<Response, ApiError> {
    reject_unsupported_idempotency(&headers)?;
    let Json(request) = payload.map_err(ApiError::invalid_json)?;
    let target_account_id = AccountId::parse(request.account_id).map_err(|_| {
        ApiError::new(
            StatusCode::NOT_FOUND,
            "account_not_found",
            "Account not found",
            "The requested account is unavailable",
        )
        .with_no_store()
    })?;
    // Preferences are user-global. Read and validate them before rotating the
    // session so no fallible database read can turn a committed switch into an
    // error response that withholds the newly minted token.
    let preferences = state.store.preferences(&current.principal.authz).await?;
    user_preferences(&preferences)?;
    let (auth_session_id, session_token, csrf_token, expires_at) = fresh_auth_tokens()?;
    let result = state
        .store
        .switch_auth_session(SwitchAuthSessionCommit {
            current_authz: current.principal.authz,
            current_session_token_hash: current.session_token_hash,
            target_account_id,
            next_auth_session_id: auth_session_id,
            next_session_token_hash: session_token.digest().to_persistence(),
            next_csrf_hash: csrf_token.digest().to_persistence(),
            next_expires_at: expires_at.clone(),
        })
        .await
        .map_err(|error| match error {
            StoreError::AuthSessionNotFound | StoreError::PermissionDenied => ApiError::new(
                StatusCode::NOT_FOUND,
                "account_not_found",
                "Account not found",
                "The requested account is unavailable",
            )
            .with_no_store(),
            other => other.into(),
        })?;
    authentication_response(
        &state,
        &session_token,
        &csrf_token,
        &expires_at,
        AuthenticationSubject {
            account_id: result.account.id,
            user: result.principal.user,
            membership_role: result.account.role,
            preferences,
        },
    )
}

async fn member_setup(
    State(state): State<ApiState>,
    Extension(source): Extension<EffectiveClientIp>,
    headers: HeaderMap,
    payload: Result<Json<MemberSetupRequest>, JsonRejection>,
) -> Result<Response, ApiError> {
    enforce_same_origin(&headers, &auth_config(&state)?.ingress)?;
    let auth = auth_config(&state)?;
    charge_auth_rate_limit(
        &auth.rate_limits.member_setup,
        source.0,
        None,
        "member_setup_rate_limited",
        "Member setup temporarily limited",
    )?;
    reject_unsupported_idempotency(&headers)?;
    let Json(request) = payload.map_err(ApiError::invalid_json)?;
    let setup_token = MemberSetupToken::from_presented(request.setup_token)
        .map_err(|_| ApiError::invalid_member_setup())?;
    let password_hash = hash_new_password(auth, request.password).await?;
    let (auth_session_id, session_token, csrf_token, expires_at) = fresh_auth_tokens()?;
    let result = state
        .store
        .complete_member_setup(MemberSetupCommit {
            setup_token,
            password_hash: password_hash.as_phc().to_owned(),
            auth_session_id,
            session_token_hash: session_token.digest().to_persistence(),
            csrf_hash: csrf_token.digest().to_persistence(),
            session_expires_at: expires_at.clone(),
        })
        .await
        .map_err(|error| match error {
            StoreError::InvalidMemberSetupToken
            | StoreError::MemberSetupExpired
            | StoreError::MemberSetupAlreadyCompleted => ApiError::invalid_member_setup(),
            other => other.into(),
        })?;
    let context = result.principal.authz.clone();
    let preferences = state.store.preferences(&context).await?;
    authentication_response(
        &state,
        &session_token,
        &csrf_token,
        &expires_at,
        AuthenticationSubject {
            account_id: context.account_id,
            user: result.principal.user,
            membership_role: context.membership_role,
            preferences,
        },
    )
}

async fn hash_new_password(
    auth: &AuthConfig,
    mut presented: String,
) -> Result<PasswordHashRecord, ApiError> {
    let password_value = std::mem::take(&mut presented);
    presented.zeroize();
    let password = Password::new(password_value)
        .map_err(|error| ApiError::bad_request("invalid_password", error.to_string()))?;
    let permit = auth
        .password_workers
        .clone()
        .try_acquire_owned()
        .map_err(|_| ApiError::auth_unavailable("password workers are busy"))?;
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        hash_password(&password)
    })
    .await
    .map_err(|error| ApiError::auth_unavailable(&error))?
    .map_err(|error| ApiError::auth_unavailable(&error))
}

async fn list_members(
    State(state): State<ApiState>,
    Extension(current): Extension<CurrentAuth>,
    query: Result<Query<MemberListQuery>, QueryRejection>,
) -> Result<Response, ApiError> {
    let Query(query) = query.map_err(ApiError::invalid_query)?;
    let page = state
        .store
        .list_members(
            &current.principal.authz,
            query.cursor.as_deref(),
            query.limit.unwrap_or(COLLECTION_PAGE_DEFAULT_LIMIT),
        )
        .await?;
    json_no_store(AccountMemberPage {
        members: page.items.iter().map(account_member).collect(),
        next_cursor: page.next_cursor,
    })
}

async fn get_knowledge_catalog(
    State(state): State<ApiState>,
    Extension(current): Extension<CurrentAuth>,
) -> Result<Response, ApiError> {
    let catalog: KnowledgeCatalogState = state
        .store
        .knowledge_catalog_for_admin(&current.principal.authz)
        .await?;
    json_no_store(catalog)
}

async fn replace_knowledge_catalog(
    State(state): State<ApiState>,
    Extension(current): Extension<CurrentAuth>,
    headers: HeaderMap,
    payload: Result<Json<ReplaceKnowledgeCatalogRequest>, JsonRejection>,
) -> Result<Response, ApiError> {
    let Json(request) = payload.map_err(ApiError::invalid_json)?;
    let idempotency_key = required_idempotency_key(&headers)?;
    let result: KnowledgeCatalogUpdateResult = state
        .store
        .replace_knowledge_catalog(
            &current.principal.authz,
            request.expected_revision,
            request.entries,
            idempotency_key,
        )
        .await?;
    kick_followup_worker(&state);
    json_no_store(result)
}

async fn get_agent_prompt(
    State(state): State<ApiState>,
    Extension(current): Extension<CurrentAuth>,
) -> Result<Response, ApiError> {
    let prompt: AgentPromptState = state
        .store
        .agent_prompt_for_admin(&current.principal.authz)
        .await?;
    json_no_store(prompt)
}

async fn replace_agent_prompt(
    State(state): State<ApiState>,
    Extension(current): Extension<CurrentAuth>,
    headers: HeaderMap,
    payload: Result<Json<ReplaceAgentPromptRequest>, JsonRejection>,
) -> Result<Response, ApiError> {
    let Json(request) = payload.map_err(ApiError::invalid_json)?;
    let idempotency_key = required_idempotency_key(&headers)?;
    let result: AgentPromptUpdateResult = state
        .store
        .replace_agent_prompt(
            &current.principal.authz,
            request.expected_revision,
            request.content,
            idempotency_key,
        )
        .await?;
    kick_followup_worker(&state);
    json_no_store(result)
}

async fn list_agent_prompt_revisions(
    State(state): State<ApiState>,
    Extension(current): Extension<CurrentAuth>,
    query: Result<Query<AgentPromptRevisionListQuery>, QueryRejection>,
) -> Result<Response, ApiError> {
    let Query(query) = query.map_err(ApiError::invalid_query)?;
    let page: AgentPromptRevisionPage = state
        .store
        .agent_prompt_revisions_for_admin(
            &current.principal.authz,
            query.before_revision,
            query.limit.unwrap_or(COLLECTION_PAGE_DEFAULT_LIMIT),
        )
        .await?;
    json_no_store(page)
}

async fn get_agent_prompt_revision(
    State(state): State<ApiState>,
    Extension(current): Extension<CurrentAuth>,
    Path(revision): Path<String>,
) -> Result<Response, ApiError> {
    let parsed_revision = revision.parse::<u64>().ok();
    let revision = parsed_revision
        .filter(|parsed| parsed.to_string() == revision)
        .ok_or_else(|| {
            ApiError::bad_request(
                "invalid_agent_prompt_revision",
                "Agent prompt revision must be a canonical unsigned integer",
            )
            .with_no_store()
        })?;
    let prompt: AgentPromptState = state
        .store
        .agent_prompt_revision_for_admin(&current.principal.authz, revision)
        .await?;
    json_no_store(prompt)
}

async fn list_knowledge_catalog_revisions(
    State(state): State<ApiState>,
    Extension(current): Extension<CurrentAuth>,
    query: Result<Query<KnowledgeCatalogRevisionListQuery>, QueryRejection>,
) -> Result<Response, ApiError> {
    let Query(query) = query.map_err(ApiError::invalid_query)?;
    let page: KnowledgeCatalogRevisionPage = state
        .store
        .knowledge_catalog_revisions_for_admin(
            &current.principal.authz,
            query.before_revision,
            query.limit.unwrap_or(COLLECTION_PAGE_DEFAULT_LIMIT),
        )
        .await?;
    json_no_store(page)
}

async fn get_knowledge_catalog_revision(
    State(state): State<ApiState>,
    Extension(current): Extension<CurrentAuth>,
    Path(revision): Path<String>,
) -> Result<Response, ApiError> {
    let parsed_revision = revision.parse::<u64>().ok();
    let revision = parsed_revision
        .filter(|parsed| parsed.to_string() == revision)
        .ok_or_else(|| {
            ApiError::bad_request(
                "invalid_knowledge_catalog_revision",
                "Knowledge catalog revision must be a canonical unsigned integer",
            )
            .with_no_store()
        })?;
    let catalog: KnowledgeCatalogState = state
        .store
        .knowledge_catalog_revision_for_admin(&current.principal.authz, revision)
        .await?;
    json_no_store(catalog)
}

async fn create_member(
    State(state): State<ApiState>,
    Extension(current): Extension<CurrentAuth>,
    payload: Result<Json<CreateMemberRequest>, JsonRejection>,
) -> Result<Response, ApiError> {
    let Json(request) = payload.map_err(ApiError::invalid_json)?;
    let username = Username::parse(request.username)
        .map_err(|error| ApiError::bad_request("invalid_username", error.to_string()))?;
    let user_id = UserId::generate().map_err(|error| ApiError::auth_unavailable(&error))?;
    let issued = state
        .store
        .create_member(
            &current.principal.authz,
            user_id.as_str().to_owned(),
            username.as_str().to_owned(),
        )
        .await?;
    let (result, setup_token) = issued.into_parts();
    member_setup_token_response(result.member, setup_token, StatusCode::CREATED)
}

async fn rotate_member_setup_token(
    State(state): State<ApiState>,
    Extension(current): Extension<CurrentAuth>,
    Path(user_id): Path<String>,
    payload: Result<Json<RotateMemberSetupTokenRequest>, JsonRejection>,
) -> Result<Response, ApiError> {
    state
        .store
        .get_member(&current.principal.authz, &user_id)
        .await?;
    let Json(request) = payload.map_err(ApiError::invalid_json)?;
    let expected_revision = membership_revision(request.expected_revision)?;
    let issued = state
        .store
        .rotate_member_setup_token(&current.principal.authz, user_id, expected_revision)
        .await
        .map_err(|error| match error {
            StoreError::InvalidMemberSetupToken | StoreError::MemberSetupAlreadyCompleted => {
                ApiError::member_setup_not_pending()
            }
            other => other.into(),
        })?;
    let (result, setup_token) = issued.into_parts();
    member_setup_token_response(result.member, setup_token, StatusCode::OK)
}

async fn update_member(
    State(state): State<ApiState>,
    Extension(current): Extension<CurrentAuth>,
    Path(user_id): Path<String>,
    payload: Result<Json<UpdateMemberRequest>, JsonRejection>,
) -> Result<Response, ApiError> {
    let existing = state
        .store
        .get_member(&current.principal.authz, &user_id)
        .await?;
    let Json(request) = payload.map_err(ApiError::invalid_json)?;
    if request.role.is_none() && request.status.is_none() {
        return Err(ApiError::bad_request(
            "empty_member_update",
            "At least one of role or status must be supplied",
        ));
    }
    let expected_revision = membership_revision(request.expected_revision)?;
    let role = request.role.map(membership_role).unwrap_or(existing.role);
    let status = request
        .status
        .map(stored_membership_status)
        .unwrap_or(existing.status);
    let result = state
        .store
        .transition_member(
            &current.principal.authz,
            TransitionMemberCommit {
                user_id,
                expected_revision,
                expected_role: existing.role,
                expected_status: existing.status,
                role,
                status,
            },
        )
        .await?;
    json_no_store(UpdateMemberResponse {
        member: account_member(&result.member),
        in_flight: InFlightWorkSummary {
            reply_job_ids: result.in_flight.reply_job_ids,
            dispatch_call_ids: result.in_flight.dispatch_call_ids,
            agent_model_job_ids: result.in_flight.agent_model_job_ids,
            agent_tool_call_ids: result.in_flight.agent_tool_call_ids,
        },
    })
}

fn member_setup_token_response(
    member: StoredMember,
    setup_token: String,
    status: StatusCode,
) -> Result<Response, ApiError> {
    let setup_token_expires_at = member
        .setup_token_expires_at
        .clone()
        .ok_or_else(|| ApiError::internal_contract("issued member setup token has no expiry"))?;
    let mut response = json_no_store(MemberSetupTokenResponse {
        member: account_member(&member),
        setup_token,
        setup_token_expires_at,
    })?;
    *response.status_mut() = status;
    Ok(response)
}

fn membership_revision(value: u64) -> Result<tenancy::MembershipRevision, ApiError> {
    tenancy::MembershipRevision::new(value).map_err(|_| ApiError::membership_revision_conflict())
}

fn membership_role(role: AccountRole) -> MembershipRole {
    match role {
        AccountRole::Owner => MembershipRole::Owner,
        AccountRole::Member => MembershipRole::Member,
    }
}

fn stored_membership_status(status: AccountStatus) -> StoredMembershipStatus {
    match status {
        AccountStatus::Active => StoredMembershipStatus::Active,
        AccountStatus::Disabled => StoredMembershipStatus::Disabled,
    }
}

fn account_member(member: &StoredMember) -> AccountMember {
    AccountMember {
        user_id: member.user_id.clone(),
        username: member.username.clone(),
        role: match member.role {
            MembershipRole::Owner => AccountRole::Owner,
            MembershipRole::Member => AccountRole::Member,
        },
        status: match member.status {
            StoredMembershipStatus::Active => AccountStatus::Active,
            StoredMembershipStatus::Disabled => AccountStatus::Disabled,
        },
        revision: member.revision.get(),
        setup_required: member.setup_required,
        setup_token_expires_at: member.setup_token_expires_at.clone(),
        created_at: member.created_at.clone(),
        updated_at: member.updated_at.clone(),
    }
}

async fn list_account_audit_events(
    State(state): State<ApiState>,
    Extension(current): Extension<CurrentAuth>,
    query: Result<Query<AuditListQuery>, QueryRejection>,
) -> Result<Response, ApiError> {
    state
        .store
        .account_audit_state(&current.principal.authz)
        .await?;
    let Query(query) = query.map_err(ApiError::invalid_query)?;
    let page = state
        .store
        .list_account_audit_events(
            &current.principal.authz,
            query.cursor.as_deref(),
            query.limit.unwrap_or(COLLECTION_PAGE_DEFAULT_LIMIT),
        )
        .await?;
    json_no_store(AccountAuditEventPage {
        events: page.items.into_iter().map(account_audit_event).collect(),
        next_cursor: page.next_cursor,
        state: account_audit_state(page.state),
    })
}

async fn export_account_audit_events(
    State(state): State<ApiState>,
    Extension(current): Extension<CurrentAuth>,
) -> Result<Response, ApiError> {
    let authz = current.principal.authz;
    let mut page = state
        .store
        .list_account_audit_events(&authz, None, protocol::COLLECTION_PAGE_MAX_LIMIT)
        .await?;
    let baseline_rollup = page.state.rollup.clone();
    let expected_detailed_rows = page.state.detailed_rows;
    let expected_head_sequence = baseline_rollup
        .through_sequence
        .checked_add(expected_detailed_rows)
        .ok_or_else(|| {
            ApiError::internal_contract("account audit export sequence range overflowed")
        })?;
    let snapshot_event_count = baseline_rollup
        .event_count
        .checked_add(expected_detailed_rows)
        .ok_or_else(|| ApiError::internal_contract("account audit event count overflowed"))?;
    if snapshot_event_count != expected_head_sequence {
        return Err(ApiError::internal_contract(
            "account audit rollup count does not match its sequence boundary",
        ));
    }
    let mut seen_cursors = HashSet::new();
    let mut body = Vec::new();
    append_account_audit_ndjson_line(
        &mut body,
        &AccountAuditExportManifest {
            kind: ACCOUNT_AUDIT_EXPORT_MANIFEST_KIND.into(),
            schema_version: ACCOUNT_AUDIT_EXPORT_SCHEMA_VERSION,
            event_schema: ACCOUNT_AUDIT_EVENT_SCHEMA.into(),
            exported_at: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            rollup: account_audit_rollup(baseline_rollup.clone()),
            snapshot_head_sequence: expected_head_sequence,
            snapshot_event_count,
            detailed_event_count: expected_detailed_rows,
        },
        ACCOUNT_AUDIT_EXPORT_MAX_BYTES,
    )?;
    let mut exported_rows = 0_u64;
    let mut newer_chain_link: Option<(u64, String)> = None;
    let mut oldest_chain_link: Option<(u64, String)> = None;
    loop {
        if page.state.rollup != baseline_rollup {
            return Err(ApiError::new(
                StatusCode::CONFLICT,
                "audit_export_changed",
                "Account audit changed",
                "Detailed audit history was compacted while the export was being prepared; retry the export",
            )
            .with_no_store());
        }
        let next_cursor = page.next_cursor.take();
        for event in page.items {
            let event = account_audit_event(event);
            if let Some((newer_sequence, newer_previous_hash)) = &newer_chain_link {
                if newer_sequence.checked_sub(1) != Some(event.sequence)
                    || newer_previous_hash != &event.event_hash
                {
                    return Err(ApiError::internal_contract(
                        "account audit export rows are not one contiguous hash chain",
                    ));
                }
            } else if event.sequence != expected_head_sequence {
                return Err(ApiError::internal_contract(
                    "account audit export head does not match durable state",
                ));
            }
            exported_rows = exported_rows.checked_add(1).ok_or_else(|| {
                ApiError::internal_contract("account audit export row count overflowed")
            })?;
            newer_chain_link = Some((event.sequence, event.previous_hash.clone()));
            oldest_chain_link = Some((event.sequence, event.previous_hash.clone()));

            append_account_audit_ndjson_line(&mut body, &event, ACCOUNT_AUDIT_EXPORT_MAX_BYTES)?;
        }
        let Some(cursor) = next_cursor else {
            break;
        };
        if !seen_cursors.insert(cursor.clone()) {
            return Err(ApiError::internal_contract(
                "account audit export pagination repeated a cursor",
            ));
        }
        page = state
            .store
            .list_account_audit_events(&authz, Some(&cursor), protocol::COLLECTION_PAGE_MAX_LIMIT)
            .await?;
    }
    if exported_rows != expected_detailed_rows {
        return Err(ApiError::internal_contract(
            "account audit export row count does not match durable state",
        ));
    }
    match oldest_chain_link {
        Some((oldest_sequence, oldest_previous_hash))
            if baseline_rollup
                .through_sequence
                .checked_add(1)
                .is_some_and(|expected| expected == oldest_sequence)
                && oldest_previous_hash == baseline_rollup.last_event_hash => {}
        None if expected_detailed_rows == 0 => {}
        _ => {
            return Err(ApiError::internal_contract(
                "account audit export boundary does not match the durable rollup",
            ));
        }
    }
    let mut response = Response::new(Body::from(body));
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/x-ndjson"),
    );
    response.headers_mut().insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_static("attachment; filename=zeus-account-audit.ndjson"),
    );
    no_store(response.headers_mut());
    Ok(response)
}

fn append_account_audit_ndjson_line<T: Serialize>(
    body: &mut Vec<u8>,
    value: &T,
    max_bytes: usize,
) -> Result<(), ApiError> {
    let encoded = serde_json::to_vec(value).map_err(|error| {
        eprintln!("zeus account audit export serialization failed: {error}");
        ApiError::internal_contract("account audit export value could not be serialized")
    })?;
    let required = encoded
        .len()
        .checked_add(1)
        .ok_or_else(|| ApiError::audit_export_too_large(max_bytes))?;
    let maximum_prior_length = max_bytes
        .checked_sub(required)
        .ok_or_else(|| ApiError::audit_export_too_large(max_bytes))?;
    if body.len() > maximum_prior_length {
        return Err(ApiError::audit_export_too_large(max_bytes));
    }
    body.try_reserve(required).map_err(|error| {
        eprintln!("zeus account audit export allocation failed: {error}");
        ApiError::audit_export_too_large(max_bytes)
    })?;
    body.extend_from_slice(&encoded);
    body.push(b'\n');
    Ok(())
}

async fn get_account_audit_policy(
    State(state): State<ApiState>,
    Extension(current): Extension<CurrentAuth>,
) -> Result<Response, ApiError> {
    let state = state
        .store
        .account_audit_state(&current.principal.authz)
        .await?;
    json_no_store(account_audit_policy(state.policy))
}

async fn update_account_audit_policy(
    State(state): State<ApiState>,
    Extension(current): Extension<CurrentAuth>,
    payload: Result<Json<UpdateAccountAuditPolicyRequest>, JsonRejection>,
) -> Result<Response, ApiError> {
    state
        .store
        .account_audit_state(&current.principal.authz)
        .await?;
    let Json(request) = payload.map_err(ApiError::invalid_json)?;
    let state = state
        .store
        .update_account_audit_policy(
            &current.principal.authz,
            UpdateAccountAuditPolicyCommit {
                expected_revision: request.expected_revision,
                detail_rows: request.detail_rows,
                legal_hold: request.legal_hold,
                archive_required: request.archive_required,
            },
        )
        .await?;
    json_no_store(account_audit_policy(state.policy))
}

async fn checkpoint_account_audit_archive(
    State(state): State<ApiState>,
    Extension(current): Extension<CurrentAuth>,
    payload: Result<Json<CreateAccountAuditCheckpointRequest>, JsonRejection>,
) -> Result<Response, ApiError> {
    state
        .store
        .account_audit_state(&current.principal.authz)
        .await?;
    let Json(request) = payload.map_err(ApiError::invalid_json)?;
    let state = state
        .store
        .checkpoint_account_audit_archive(
            &current.principal.authz,
            AccountAuditCheckpointCommit {
                expected_revision: request.expected_revision,
                through_sequence: request.through_sequence,
                event_hash: request.event_hash,
                archive_reference: request.archive_reference,
            },
        )
        .await?;
    let state = account_audit_state(state);
    json_no_store(AccountAuditCheckpointResponse {
        archive: state.archive.clone(),
        state,
    })
}

fn account_audit_event(event: StoredAccountAuditEvent) -> AccountAuditEvent {
    let target_user_id =
        matches!(event.target_kind.as_str(), "member" | "user").then(|| event.target_id.clone());
    AccountAuditEvent {
        sequence: event.sequence,
        actor_user_id: event.actor_user_id,
        action: event.action,
        outcome: event.outcome,
        target_kind: event.target_kind,
        target_id: event.target_id,
        target_user_id,
        occurred_at: event.occurred_at,
        metadata: event.metadata,
        previous_hash: event.previous_hash,
        event_hash: event.event_hash,
    }
}

fn account_audit_policy(policy: StoredAccountAuditPolicy) -> AccountAuditPolicyResponse {
    AccountAuditPolicyResponse {
        detail_rows: policy.detail_rows,
        legal_hold: policy.legal_hold,
        archive_required: policy.archive_required,
        revision: policy.revision,
        updated_at: policy.updated_at,
    }
}

fn account_audit_rollup(rollup: StoredAccountAuditRollup) -> AccountAuditRollupResponse {
    AccountAuditRollupResponse {
        through_sequence: rollup.through_sequence,
        digest: rollup.digest,
        event_count: rollup.event_count,
        last_event_hash: rollup.last_event_hash,
        updated_at: rollup.updated_at,
    }
}

fn account_audit_state(state: StoredAccountAuditState) -> AccountAuditStateResponse {
    AccountAuditStateResponse {
        policy: account_audit_policy(state.policy),
        rollup: account_audit_rollup(state.rollup),
        archive: AccountAuditArchiveStateResponse {
            through_sequence: state.archive.through_sequence,
            event_hash: state.archive.event_hash,
            archive_reference: state.archive.archive_reference,
            revision: state.archive.revision,
            updated_at: state.archive.updated_at,
        },
        detailed_rows: state.detailed_rows,
        ordinary_capacity_remaining: state.ordinary_capacity_remaining,
        progress_capacity_remaining: state.progress_capacity_remaining,
    }
}

async fn logout(
    State(state): State<ApiState>,
    Extension(current): Extension<CurrentAuth>,
) -> Result<Response, ApiError> {
    state
        .store
        .revoke_auth_session(&current.principal.authz, &current.session_token_hash)
        .await?;
    let mut response = Json(LogoutResponse {
        status: "signed_out".into(),
    })
    .into_response();
    clear_auth_cookies(
        response.headers_mut(),
        auth_config(&state)?.ingress.cookie_secure(),
    )?;
    no_store(response.headers_mut());
    Ok(response)
}

async fn get_preferences(
    State(state): State<ApiState>,
    Extension(current): Extension<CurrentAuth>,
) -> Result<Json<UserPreferences>, ApiError> {
    let preferences = state.store.preferences(&current.principal.authz).await?;
    Ok(Json(user_preferences(&preferences)?))
}

async fn patch_preferences(
    State(state): State<ApiState>,
    Extension(current): Extension<CurrentAuth>,
    payload: Result<Json<UpdatePreferencesRequest>, JsonRejection>,
) -> Result<Json<UserPreferences>, ApiError> {
    let Json(request) = payload.map_err(ApiError::invalid_json)?;
    let theme = match request.theme {
        ThemePreference::System => "system",
        ThemePreference::Light => "light",
        ThemePreference::Dark => "dark",
    };
    let preferred_model = request.preferred_model.as_deref();
    if let Some(preferred_model) = preferred_model {
        protocol::validate_reply_model_id(preferred_model).map_err(|error| {
            ApiError::bad_request("unsupported_model", format!("The preferred model {error}"))
        })?;
    }
    let executor = reply_executor(&state)?;
    let selected =
        selected_provider_for_actor(&state.store, executor, &current.principal.authz).await?;
    let metadata = provider_for_state(executor, &selected)?.metadata();
    if preferred_model.is_some() && preferred_model != metadata.model.as_deref() {
        return Err(ApiError::bad_request(
            "unsupported_model",
            "The preferred model must match the server-configured provider model",
        ));
    }
    let preferences = state
        .store
        .update_preferences(
            &current.principal.authz,
            request.expected_revision,
            theme,
            preferred_model,
        )
        .await?;
    Ok(Json(user_preferences(&preferences)?))
}

async fn get_reply_provider_catalog(
    State(state): State<ApiState>,
    Extension(current): Extension<CurrentAuth>,
) -> Result<Response, ApiError> {
    let executor = reply_executor(&state)?;
    for provider in executor.providers.providers.values() {
        validate_provider_metadata(provider.metadata()).map_err(ApiError::reply_unavailable)?;
    }
    let selected =
        selected_provider_for_actor(&state.store, executor, &current.principal.authz).await?;
    provider_for_state(executor, &selected)?;
    json_no_store(ReplyProviderCatalogResponse {
        default_provider_id: executor.providers.default_provider_id.clone(),
        selected_provider_id: selected.provider_id,
        selected_revision: selected.revision,
        providers: executor.providers.descriptors(),
    })
}

async fn get_account_reply_provider(
    State(state): State<ApiState>,
    Extension(current): Extension<CurrentAuth>,
) -> Result<Response, ApiError> {
    let executor = reply_executor(&state)?;
    let selected =
        selected_provider_for_actor(&state.store, executor, &current.principal.authz).await?;
    provider_for_state(executor, &selected)?;
    json_no_store(selected)
}

async fn update_account_reply_provider(
    State(state): State<ApiState>,
    Extension(current): Extension<CurrentAuth>,
    headers: HeaderMap,
    payload: Result<Json<UpdateAccountReplyProviderRequest>, JsonRejection>,
) -> Result<Response, ApiError> {
    let Json(request) = payload.map_err(ApiError::invalid_json)?;
    protocol::validate_reply_provider_id(&request.provider_id).map_err(|error| {
        ApiError::bad_request(
            "invalid_provider_id",
            format!("The reply provider ID {error}"),
        )
        .with_no_store()
    })?;
    let idempotency_key = required_idempotency_key(&headers)?;
    let executor = reply_executor(&state)?;
    let provider = executor
        .providers
        .get(&request.provider_id)
        .ok_or_else(|| {
            ApiError::new(
                StatusCode::NOT_FOUND,
                "reply_provider_not_found",
                "Reply provider not found",
                "The requested provider is not registered by this Zeus process",
            )
            .with_no_store()
        })?;
    let metadata = provider.metadata();
    validate_provider_metadata(metadata).map_err(ApiError::reply_unavailable)?;
    let result: AccountReplyProviderUpdateResult = state
        .store
        .replace_reply_provider(
            &current.principal.authz,
            request.expected_revision,
            metadata.provider_id.clone(),
            metadata.model.clone(),
            assistant_reply_kind(metadata.reply_kind),
            idempotency_key,
        )
        .await?;
    kick_followup_worker(&state);
    json_no_store(result)
}

async fn enforce_ingress(
    State(state): State<ApiState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    mut request: Request,
    next: Next,
) -> Response {
    let result = auth_config(&state).and_then(|auth| {
        effective_client_ip(&auth.ingress, peer.ip(), request.headers())
            .map_err(ApiError::from_ingress_error)
    });
    match result {
        Ok(source) => {
            request.extensions_mut().insert(EffectiveClientIp(source));
            next.run(request).await
        }
        Err(error) => error.into_response(),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum IngressRequestError {
    UntrustedPeer,
    InvalidForwarded,
}

fn effective_client_ip(
    policy: &IngressPolicy,
    peer: IpAddr,
    headers: &HeaderMap,
) -> Result<IpAddr, IngressRequestError> {
    let IngressPolicy::TrustedProxy(config) = policy else {
        return Ok(peer);
    };
    if !config
        .trusted_proxies
        .iter()
        .any(|network| network.contains(peer))
    {
        return Err(IngressRequestError::UntrustedPeer);
    }
    parse_forwarded_client(headers, &config.public_authority)
}

fn parse_forwarded_client(
    headers: &HeaderMap,
    public_authority: &str,
) -> Result<IpAddr, IngressRequestError> {
    let forwarded =
        exactly_one_header(headers, "forwarded").ok_or(IngressRequestError::InvalidForwarded)?;
    if forwarded.contains(',') {
        return Err(IngressRequestError::InvalidForwarded);
    }
    let mut client = None;
    let mut proto = None;
    let mut host = None;
    for parameter in forwarded.split(';') {
        if parameter.is_empty() || parameter.trim() != parameter {
            return Err(IngressRequestError::InvalidForwarded);
        }
        let (name, raw_value) = parameter
            .split_once('=')
            .ok_or(IngressRequestError::InvalidForwarded)?;
        let value =
            canonical_forwarded_value(raw_value).ok_or(IngressRequestError::InvalidForwarded)?;
        match name {
            "for" if client.is_none() => {
                let address =
                    parse_forwarded_for(raw_value).ok_or(IngressRequestError::InvalidForwarded)?;
                if address.is_unspecified() {
                    return Err(IngressRequestError::InvalidForwarded);
                }
                client = Some(address);
            }
            "proto" if proto.is_none() => proto = Some(value),
            "host" if host.is_none() => host = Some(value),
            _ => return Err(IngressRequestError::InvalidForwarded),
        }
    }
    if proto != Some("https") || host != Some(public_authority) {
        return Err(IngressRequestError::InvalidForwarded);
    }
    client.ok_or(IngressRequestError::InvalidForwarded)
}

fn parse_forwarded_for(value: &str) -> Option<IpAddr> {
    if let Ok(IpAddr::V4(address)) = value.parse::<IpAddr>() {
        return Some(IpAddr::V4(address));
    }
    let address = value
        .strip_prefix("\"[")?
        .strip_suffix("]\"")?
        .parse::<IpAddr>()
        .ok()?;
    matches!(address, IpAddr::V6(_)).then_some(address)
}

fn canonical_forwarded_value(value: &str) -> Option<&str> {
    if value.is_empty() {
        return None;
    }
    if let Some(inner) = value
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
    {
        return (!inner.is_empty() && !inner.contains(['"', '\\'])).then_some(inner);
    }
    (!value.contains(['"', '\\', ' ', '\t'])).then_some(value)
}

fn exactly_one_header<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    let mut values = headers.get_all(name).iter();
    let value = values.next()?.to_str().ok()?;
    values.next().is_none().then_some(value)
}

async fn require_auth(State(state): State<ApiState>, mut request: Request, next: Next) -> Response {
    let result = async {
        let headers = request.headers();
        let token = cookie_value(headers, SESSION_COOKIE).ok_or_else(ApiError::unauthorized)?;
        let digest = SessionTokenDigest::from_presented(&token)
            .map_err(|_| ApiError::unauthorized())?
            .to_persistence();
        let principal = state
            .store
            .authenticate(&digest)
            .await?
            .ok_or_else(ApiError::unauthorized)?;
        if is_unsafe_method(request.method()) {
            enforce_same_origin(headers, &auth_config(&state)?.ingress)?;
            let presented = headers
                .get(CSRF_HEADER)
                .and_then(|value| value.to_str().ok())
                .ok_or_else(ApiError::invalid_csrf)?;
            let stored = CsrfTokenDigest::from_persistence(&principal.csrf_hash)
                .map_err(|error| ApiError::auth_unavailable(&error))?;
            if !stored.verify(presented) {
                return Err(ApiError::invalid_csrf());
            }
        }

        request.extensions_mut().insert(CurrentAuth {
            principal,
            session_token_hash: digest,
        });
        Ok::<_, ApiError>(next.run(request).await)
    }
    .await;
    result.unwrap_or_else(IntoResponse::into_response)
}

async fn require_account_owner(request: Request, next: Next) -> Response {
    let Some(current) = request.extensions().get::<CurrentAuth>() else {
        return ApiError::unauthorized().into_response();
    };
    if current.principal.authz.membership_role != MembershipRole::Owner {
        return ApiError::permission_denied().into_response();
    }
    next.run(request).await
}

async fn reject_unsupported_account_admin_idempotency(request: Request, next: Next) -> Response {
    if is_unsafe_method(request.method())
        && let Err(error) = reject_unsupported_idempotency(request.headers())
    {
        return error.into_response();
    }
    next.run(request).await
}

fn reject_unsupported_idempotency(headers: &HeaderMap) -> Result<(), ApiError> {
    if headers.contains_key("idempotency-key") {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "idempotency_not_supported",
            "Idempotency is not supported",
            "This endpoint does not accept Idempotency-Key; refresh durable state after an indeterminate response",
        )
        .with_no_store());
    }
    Ok(())
}

const SESSION_COOKIE: &str = "zeus_session";
const CSRF_COOKIE: &str = "zeus_csrf";
const CSRF_HEADER: &str = "x-csrf-token";
const AUTH_SESSION_SECONDS: i64 = 30 * 24 * 60 * 60;

fn auth_config(state: &ApiState) -> Result<&AuthConfig, ApiError> {
    state
        .auth
        .as_deref()
        .ok_or_else(|| ApiError::auth_unavailable("authentication is not configured"))
}

fn charge_auth_rate_limit(
    limiter: &AttemptRateLimiter,
    source: IpAddr,
    account: Option<&str>,
    code: &'static str,
    title: &'static str,
) -> Result<(), ApiError> {
    match limiter.charge(source, account) {
        Ok(()) => Ok(()),
        Err(RateLimitError::Limited(retry_after)) => {
            Err(ApiError::rate_limited(code, title, retry_after))
        }
        Err(RateLimitError::Unavailable) => Err(ApiError::auth_unavailable(
            "authentication rate limiter state is unavailable",
        )),
    }
}

fn acquire_sse_lease(capacity: &SseCapacity, context: &AuthzContext) -> Result<SseLease, ApiError> {
    match capacity.try_acquire(context) {
        Ok(lease) => Ok(lease),
        Err(RateLimitError::Limited(retry_after)) => {
            Err(ApiError::sse_capacity_exceeded(retry_after))
        }
        Err(RateLimitError::Unavailable) => Err(ApiError::unavailable_message(
            "SSE connection capacity is temporarily unavailable",
        )),
    }
}

fn fresh_auth_tokens() -> Result<(AuthSessionId, SessionToken, CsrfToken, String), ApiError> {
    let auth_session_id =
        AuthSessionId::generate().map_err(|error| ApiError::auth_unavailable(&error))?;
    let session = SessionToken::generate().map_err(|error| ApiError::auth_unavailable(&error))?;
    let csrf = CsrfToken::generate().map_err(|error| ApiError::auth_unavailable(&error))?;
    let expires_at = (chrono::Utc::now() + chrono::Duration::seconds(AUTH_SESSION_SECONDS))
        .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    Ok((auth_session_id, session, csrf, expires_at))
}

struct AuthenticationSubject {
    account_id: AccountId,
    user: StoredUser,
    membership_role: MembershipRole,
    preferences: StoredPreferences,
}

fn authentication_response(
    state: &ApiState,
    session_token: &SessionToken,
    csrf_token: &CsrfToken,
    expires_at: &str,
    subject: AuthenticationSubject,
) -> Result<Response, ApiError> {
    let mut response = Json(AuthenticationResponse {
        account_id: subject.account_id.as_str().to_owned(),
        user: account_user(&subject.user, subject.membership_role),
        preferences: user_preferences(&subject.preferences)?,
        csrf_token: csrf_token.expose_secret().to_owned(),
        expires_at: expires_at.to_owned(),
    })
    .into_response();
    set_auth_cookies(
        response.headers_mut(),
        session_token.expose_secret(),
        csrf_token.expose_secret(),
        auth_config(state)?.ingress.cookie_secure(),
    )?;
    no_store(response.headers_mut());
    Ok(response)
}

fn account_summary(account: StoredAccount) -> AccountSummary {
    AccountSummary {
        id: account.id.as_str().to_owned(),
        name: account.name,
        status: match account.status {
            StoredAccountStatus::Active => AccountLifecycleStatus::Active,
            StoredAccountStatus::Suspended => AccountLifecycleStatus::Suspended,
        },
        role: match account.role {
            MembershipRole::Owner => AccountRole::Owner,
            MembershipRole::Member => AccountRole::Member,
        },
        membership_status: match account.membership_status {
            StoredMembershipStatus::Active => AccountStatus::Active,
            StoredMembershipStatus::Disabled => AccountStatus::Disabled,
        },
        membership_revision: account.membership_revision.get(),
        created_at: account.created_at,
        updated_at: account.updated_at,
    }
}

async fn authenticate_headers(
    state: &ApiState,
    headers: &HeaderMap,
) -> Result<Option<AuthPrincipal>, ApiError> {
    let Some(token) = cookie_value(headers, SESSION_COOKIE) else {
        return Ok(None);
    };
    let Ok(digest) = SessionTokenDigest::from_presented(&token) else {
        return Ok(None);
    };
    Ok(state.store.authenticate(&digest.to_persistence()).await?)
}

fn account_user(user: &StoredUser, membership_role: MembershipRole) -> AccountUser {
    AccountUser {
        id: user.id.clone(),
        username: user.username.clone(),
        role: match membership_role {
            MembershipRole::Owner => AccountRole::Owner,
            MembershipRole::Member => AccountRole::Member,
        },
        status: match user.status {
            StoredUserStatus::Active => AccountStatus::Active,
            StoredUserStatus::Disabled => AccountStatus::Disabled,
        },
        created_at: user.created_at.clone(),
    }
}

fn user_preferences(preferences: &StoredPreferences) -> Result<UserPreferences, ApiError> {
    let theme = match preferences.theme.as_str() {
        "system" => ThemePreference::System,
        "light" => ThemePreference::Light,
        "dark" => ThemePreference::Dark,
        other => {
            return Err(ApiError::auth_unavailable(&format!(
                "invalid stored theme {other}"
            )));
        }
    };
    Ok(UserPreferences {
        theme,
        preferred_model: preferences.preferred_model.clone(),
        revision: preferences.revision,
        updated_at: preferences.updated_at.clone(),
    })
}

fn enforce_same_origin(headers: &HeaderMap, policy: &IngressPolicy) -> Result<(), ApiError> {
    let origin = exactly_one_header(headers, header::ORIGIN.as_str())
        .ok_or_else(ApiError::invalid_origin)?;
    if let IngressPolicy::TrustedProxy(config) = policy {
        return (origin == config.public_origin)
            .then_some(())
            .ok_or_else(ApiError::invalid_origin);
    }
    let host =
        exactly_one_header(headers, header::HOST.as_str()).ok_or_else(ApiError::invalid_origin)?;
    let uri = origin
        .parse::<Uri>()
        .map_err(|_| ApiError::invalid_origin())?;
    if !matches!(uri.scheme_str(), Some("http" | "https"))
        || uri.path() != "/"
        || uri.query().is_some()
    {
        return Err(ApiError::invalid_origin());
    }
    let authority = uri
        .authority()
        .map(|authority| authority.as_str())
        .ok_or_else(ApiError::invalid_origin)?;
    if !authority.eq_ignore_ascii_case(host) {
        return Err(ApiError::invalid_origin());
    }
    Ok(())
}

fn is_unsafe_method(method: &Method) -> bool {
    !matches!(*method, Method::GET | Method::HEAD | Method::OPTIONS)
}

fn cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    headers.get_all(header::COOKIE).iter().find_map(|header| {
        header.to_str().ok()?.split(';').find_map(|part| {
            let (cookie_name, value) = part.trim().split_once('=')?;
            (cookie_name == name).then(|| value.to_owned())
        })
    })
}

fn set_auth_cookies(
    headers: &mut HeaderMap,
    session_token: &str,
    csrf_token: &str,
    secure: bool,
) -> Result<(), ApiError> {
    let secure_attribute = if secure { "; Secure" } else { "" };
    append_cookie(
        headers,
        format!(
            "{SESSION_COOKIE}={session_token}; Path=/; HttpOnly; SameSite=Strict; Max-Age={AUTH_SESSION_SECONDS}{}",
            secure_attribute
        ),
    )?;
    append_cookie(
        headers,
        format!(
            "{CSRF_COOKIE}={csrf_token}; Path=/; SameSite=Strict; Max-Age={AUTH_SESSION_SECONDS}{}",
            secure_attribute
        ),
    )
}

fn clear_auth_cookies(headers: &mut HeaderMap, secure: bool) -> Result<(), ApiError> {
    let secure = if secure { "; Secure" } else { "" };
    append_cookie(
        headers,
        format!("{SESSION_COOKIE}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0{secure}"),
    )?;
    append_cookie(
        headers,
        format!("{CSRF_COOKIE}=; Path=/; SameSite=Strict; Max-Age=0{secure}"),
    )
}

fn append_cookie(headers: &mut HeaderMap, value: String) -> Result<(), ApiError> {
    let value =
        HeaderValue::from_str(&value).map_err(|error| ApiError::auth_unavailable(&error))?;
    headers.append(header::SET_COOKIE, value);
    Ok(())
}

fn no_store(headers: &mut HeaderMap) {
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
}

fn json_no_store<T: Serialize>(value: T) -> Result<Response, ApiError> {
    let mut response = Json(value).into_response();
    no_store(response.headers_mut());
    Ok(response)
}

fn reply_executor(state: &ApiState) -> Result<&ReplyExecutor, ApiError> {
    state
        .reply
        .as_deref()
        .ok_or_else(|| ApiError::auth_unavailable("reply execution is not configured"))
}

fn kick_reply_worker(state: &ApiState) {
    let Ok(runtime) = tokio::runtime::Handle::try_current() else {
        return;
    };
    let Some(reply) = &state.reply else {
        return;
    };
    if !reply.reply_worker_wake.request() {
        return;
    }
    let state = state.clone();
    runtime.spawn(async move {
        let mut retry_delay = WORKER_ERROR_RETRY_DELAY;
        loop {
            match drain_reply_jobs(&state).await {
                Err(error) if error.is_retryable_durable_completion_error() => {
                    eprintln!("zeus reply worker retrying durable queue: {error}");
                    let reply = state
                        .reply
                        .as_ref()
                        .expect("a scheduled reply worker requires a provider");
                    reply.reply_worker_wake.request();
                    tokio::time::sleep(retry_delay).await;
                    retry_delay = retry_delay
                        .saturating_mul(2)
                        .min(WORKER_ERROR_RETRY_MAX_DELAY);
                }
                Err(error) => {
                    eprintln!("zeus reply worker stopped on a permanent queue error: {error}");
                    retry_delay = WORKER_ERROR_RETRY_DELAY;
                }
                Ok(()) => retry_delay = WORKER_ERROR_RETRY_DELAY,
            }
            let reply = state
                .reply
                .as_ref()
                .expect("a scheduled reply worker requires a provider");
            if !reply.reply_worker_wake.complete_cycle() {
                return;
            }
        }
    });
}

async fn drain_reply_jobs(state: &ApiState) -> Result<(), StoreError> {
    let reply = state
        .reply
        .as_ref()
        .expect("reply worker is only started when a provider exists");
    let _drain = reply.reply_drain.lock().await;
    loop {
        let job = match state.store.claim_next_reply().await? {
            ReplyClaimOutcome::Claimed(job) => *job,
            ReplyClaimOutcome::Rejected(_) => continue,
            ReplyClaimOutcome::NotAvailable => return Ok(()),
        };
        process_reply_job(state, job).await?;
    }
}

async fn process_reply_job(state: &ApiState, job: ReplyJob) -> Result<(), StoreError> {
    let reply = state
        .reply
        .as_ref()
        .expect("a claimed reply requires a configured provider");
    let Some(provider) = reply.providers.get(&job.provider_name).cloned() else {
        return fail_reply_job(
            state,
            &job,
            "provider_configuration_changed",
            "The queued reply provider is not registered by this Zeus process",
        )
        .await;
    };
    let metadata = provider.metadata().clone();
    if validate_provider_metadata(&metadata).is_err() {
        return fail_reply_job(
            state,
            &job,
            "provider_configuration_invalid",
            "The configured reply provider exceeds the durable resource envelope",
        )
        .await;
    }
    if job.provider_name != metadata.provider_id || job.model_name != metadata.model {
        return fail_reply_job(
            state,
            &job,
            "provider_configuration_changed",
            "The queued reply no longer matches the configured provider",
        )
        .await;
    }

    let request = match serde_json::from_value::<ReplyRequest>(job.request_json.clone()) {
        Ok(request) => request,
        Err(_) => {
            return fail_reply_job(
                state,
                &job,
                "invalid_persisted_request",
                "The persisted reply request could not be decoded safely",
            )
            .await;
        }
    };
    if !persisted_reply_request_fits_envelope(&request) {
        return fail_reply_job(
            state,
            &job,
            "persisted_request_exceeds_resource_envelope",
            "The persisted reply request exceeds the configured resource envelope",
        )
        .await;
    }
    let provider_request = request.clone();
    let response = match tokio::spawn(async move { provider.reply(provider_request).await }).await {
        Ok(Ok(response)) => response,
        Ok(Err(error)) => {
            if matches!(&error, ProviderError::Timeout | ProviderError::Transport) {
                return mark_reply_outcome_unknown(
                    state,
                    &job,
                    provider_error_code(&error),
                    provider_error_message(&error),
                )
                .await;
            }
            return fail_reply_job(
                state,
                &job,
                provider_error_code(&error),
                provider_error_message(&error),
            )
            .await;
        }
        Err(_) => {
            eprintln!("zeus reply provider task panicked; settling outcome_unknown");
            return mark_reply_outcome_unknown(
                state,
                &job,
                "provider_panicked",
                "The reply provider stopped unexpectedly after the durable start checkpoint",
            )
            .await;
        }
    };
    if let Err(error) = validate_reply_response_for_request(&request, &response) {
        return fail_reply_job(
            state,
            &job,
            provider_error_code(&error),
            provider_error_message(&error),
        )
        .await;
    }
    if response.provider != metadata {
        return fail_reply_job(
            state,
            &job,
            "provider_metadata_mismatch",
            "The reply provider returned inconsistent provenance",
        )
        .await;
    }

    let assistant_message = match &response.output {
        ReplyOutput::Final { content } => content.clone(),
        ReplyOutput::ToolCall { .. } => {
            return fail_reply_job(
                state,
                &job,
                "legacy_reply_tool_call_unsupported",
                "Legacy reply work cannot admit a tool call",
            )
            .await;
        }
    };
    let expected_sequence = state
        .store
        .session_summary_for_progress(&job.session_id)
        .await?
        .sequence;
    let response_json = match serde_json::to_value(&response) {
        Ok(value) => value,
        Err(_) => {
            return fail_reply_job(
                state,
                &job,
                "invalid_provider_response",
                "The reply provider response could not be persisted safely",
            )
            .await;
        }
    };
    state
        .store
        .complete_reply_success(ReplySuccessCommit {
            job_id: job.id,
            expected_sequence,
            assistant_message,
            provenance: AssistantReplyProvenance {
                provider_id: response.provider.provider_id,
                model: response.provider.model,
                reply_kind: match response.provider.reply_kind {
                    ReplyKind::Model => AssistantReplyKind::Model,
                    ReplyKind::NonModelFallback => AssistantReplyKind::NonModelFallback,
                },
            },
            response_json,
        })
        .await?;
    kick_followup_worker(state);
    Ok(())
}

fn persisted_reply_request_fits_envelope(request: &ReplyRequest) -> bool {
    validate_reply_request(request).is_ok()
}

async fn fail_reply_job(
    state: &ApiState,
    job: &ReplyJob,
    code: &str,
    message: &str,
) -> Result<(), StoreError> {
    let expected_sequence = state
        .store
        .session_summary_for_progress(&job.session_id)
        .await?
        .sequence;
    state
        .store
        .complete_reply_failure(ReplyFailureCommit {
            job_id: job.id.clone(),
            expected_sequence,
            error_json: serde_json::json!({
                "code": code,
                "message": message,
            }),
        })
        .await?;
    Ok(())
}

async fn mark_reply_outcome_unknown(
    state: &ApiState,
    job: &ReplyJob,
    code: &str,
    message: &str,
) -> Result<(), StoreError> {
    let expected_sequence = state
        .store
        .session_summary_for_progress(&job.session_id)
        .await?
        .sequence;
    state
        .store
        .complete_reply_outcome_unknown(ReplyOutcomeUnknownCommit {
            job_id: job.id.clone(),
            expected_sequence,
            error_json: serde_json::json!({
                "code": code,
                "message": message,
            }),
        })
        .await?;
    Ok(())
}

fn provider_error_code(error: &ProviderError) -> &'static str {
    match error {
        ProviderError::InvalidConfiguration(_) => "provider_configuration_invalid",
        ProviderError::InvalidRequest(_) => "provider_request_invalid",
        ProviderError::SecretUnavailable => "provider_secret_unavailable",
        ProviderError::Timeout => "provider_timeout",
        ProviderError::Transport => "provider_transport_failed",
        ProviderError::HttpStatus { .. } => "provider_http_error",
        ProviderError::ResponseTooLarge { .. } => "provider_response_too_large",
        ProviderError::TerminalPayloadTooLarge { .. } => "provider_reply_too_large",
        ProviderError::InvalidResponse => "provider_response_invalid",
    }
}

fn provider_error_message(error: &ProviderError) -> &'static str {
    match error {
        ProviderError::InvalidConfiguration(_) => "The reply provider configuration is invalid",
        ProviderError::InvalidRequest(_) => "The reply provider rejected the request contract",
        ProviderError::SecretUnavailable => "The reply provider credential is unavailable",
        ProviderError::Timeout => "The reply provider request timed out",
        ProviderError::Transport => "The reply provider transport failed",
        ProviderError::HttpStatus { .. } => "The reply provider returned an HTTP error",
        ProviderError::ResponseTooLarge { .. } => {
            "The reply provider HTTP response exceeded its byte limit"
        }
        ProviderError::TerminalPayloadTooLarge { .. } => {
            "The reply provider output exceeded the durable terminal limit"
        }
        ProviderError::InvalidResponse => "The reply provider returned an invalid response",
    }
}

fn assistant_reply_kind(kind: ReplyKind) -> AssistantReplyKind {
    match kind {
        ReplyKind::Model => AssistantReplyKind::Model,
        ReplyKind::NonModelFallback => AssistantReplyKind::NonModelFallback,
    }
}

fn provider_for_state<'a>(
    executor: &'a ReplyExecutor,
    selected: &AccountReplyProviderState,
) -> Result<&'a Arc<dyn ReplyProvider>, ApiError> {
    let provider = executor
        .providers
        .get(&selected.provider_id)
        .ok_or_else(|| {
            ApiError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "selected_provider_unavailable",
                "Selected provider unavailable",
                "The account-selected reply provider is not registered by this Zeus process",
            )
            .with_no_store()
        })?;
    let metadata = provider.metadata();
    validate_provider_metadata(metadata).map_err(ApiError::reply_unavailable)?;
    if metadata.provider_id != selected.provider_id
        || metadata.model != selected.model
        || assistant_reply_kind(metadata.reply_kind) != selected.reply_kind
    {
        return Err(ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "selected_provider_binding_changed",
            "Selected provider binding changed",
            "The registered provider metadata no longer matches the durable account selection",
        )
        .with_no_store());
    }
    Ok(provider)
}

async fn selected_provider_for_actor(
    store: &DemoStore,
    executor: &ReplyExecutor,
    context: &AuthzContext,
) -> Result<AccountReplyProviderState, ApiError> {
    let default = executor.providers.default_state(context.account_id.clone());
    store
        .session_reply_provider_for_actor(context, default)
        .await
        .map_err(ApiError::from)
}

async fn current_agent_manifest(
    store: &DemoStore,
    account_id: &AccountId,
    provider_id: &str,
    model: Option<&str>,
    reply_kind: AssistantReplyKind,
) -> Result<ManifestEnvelope, StoreError> {
    let prompt = store
        .current_session_agent_prompt_for_account(account_id)
        .await?;
    store.session_agent_manifest_with_prompt(
        &prompt,
        provider_id.to_owned(),
        model.map(ToOwned::to_owned),
        reply_kind,
    )
}

async fn prepare_agent_subagent_spawn(
    state: &ApiState,
    work: &AgentToolWork,
) -> Result<AgentSubagentSpawnCommit, StoreError> {
    let request = subagents::prepare_spawn_agent(&work.call.arguments_json)
        .map_err(|error| StoreError::InvalidAgentTransition(error.to_string()))?;
    let scope = ExecutionScope::new(
        work.call.account_id.as_str(),
        work.model_job.actor_user_id.as_str(),
        work.call.session_id.as_str(),
        work.call.turn_id.as_str(),
        work.call.agent_id.as_str(),
    )
    .map_err(|error| StoreError::InvalidAgentTransition(error.to_string()))?;
    let candidate = state
        .store
        .subagent_spawn_candidate_for_started_tool(&scope, &work.call.call_id)
        .await?;
    let identity = subagents::spawn_agent_identity(&work.call.session_id, &work.call.call_id)
        .map_err(|error| StoreError::InvalidAgentTransition(error.to_string()))?;
    let parent_request: ReplyRequest = serde_json::from_value(work.model_job.request_json.clone())
        .map_err(|error| {
            StoreError::InvalidAgentTransition(format!(
                "spawn_agent parent request is not typed: {error}"
            ))
        })?;
    let system_prompt = parent_request
        .messages
        .iter()
        .find(|message| message.role == ReplyRole::System)
        .map(|message| message.content.as_str())
        .ok_or_else(|| {
            StoreError::InvalidAgentTransition(
                "spawn_agent requires the exact parent system prompt".into(),
            )
        })?;
    validate_agent_initial_content_budget(system_prompt, request.prompt()).map_err(|_| {
        StoreError::InvalidAgentTransition(
            "spawn_agent prompt exceeds the initial model content budget".into(),
        )
    })?;
    let knowledge = state
        .store
        .current_session_agent_knowledge_context_for_account(
            &candidate.authz.account_id,
            request.prompt(),
        )
        .await?;
    let checkpoint = state
        .store
        .session_context_checkpoint_for_account(
            &candidate.authz.account_id,
            &candidate.parent_session.id,
            candidate.parent_sequence,
        )
        .await?;
    let reply_turns = state
        .store
        .session_reply_turns_after_for_account(
            &candidate.authz.account_id,
            &candidate.parent_session.id,
            checkpoint
                .as_ref()
                .map_or(0, |checkpoint| checkpoint.source_end_sequence),
            candidate.parent_sequence,
            AGENT_REQUEST_MAX_HISTORY_PAIRS_WITH_CONTEXT,
        )
        .await?;
    let mut child_request =
        ReplyRequest::from_session_history_for_agent_with_optional_system_prompt_checkpoint_and_context(
            &reply_turns,
            request.prompt().to_owned(),
            Some(system_prompt),
            checkpoint
                .as_ref()
                .map(|checkpoint| checkpoint.summary_text.as_str()),
            knowledge.snapshot.snapshot().canonical_context(),
        )
        .map_err(|error| StoreError::InvalidAgentTransition(error.to_string()))?;
    child_request.tools = agent_tools_from_manifest(&candidate.manifest);
    let request_json = persisted_agent_reply_request(&child_request)
        .map_err(|error| StoreError::InvalidAgentTransition(error.to_string()))?;
    let inherited_events = candidate
        .inherited_turns
        .checked_mul(3)
        .and_then(|count| count.checked_add(1))
        .ok_or_else(|| {
            StoreError::InvalidAgentTransition(
                "spawn_agent inherited Session sequence overflowed".into(),
            )
        })?;
    let provider = &candidate.manifest.manifest.deployment.spec.provider;
    if provider.provider_id != work.model_job.provider_name
        || provider.model != work.model_job.model_name
    {
        return Err(StoreError::InvalidAgentTransition(
            "spawn_agent parent provider differs from its deployment manifest".into(),
        ));
    }
    Ok(AgentSubagentSpawnCommit {
        parent_sequence: candidate.parent_sequence,
        fork: ForkSessionRequest {
            id: identity.session_id,
            title: request.description().to_owned(),
            through_sequence: candidate.parent_sequence,
        },
        start: StartTurnRequest {
            turn_id: identity.turn_id,
            user_message: request.prompt().to_owned(),
            expected_sequence: inherited_events,
        },
        agent: AgentTurnSpec {
            id: identity.agent_id,
            authz: candidate.authz,
            manifest: candidate.manifest,
            environment: state.store.session_agent_environment().to_owned(),
            provider_name: work.model_job.provider_name.clone(),
            model_name: work.model_job.model_name.clone(),
            request_json,
            knowledge,
        },
    })
}

fn agent_tools_from_manifest(manifest: &ManifestEnvelope) -> Vec<ReplyToolDefinition> {
    manifest
        .manifest
        .deployment
        .spec
        .tools
        .iter()
        .map(|tool| {
            ReplyToolDefinition::new(tool.name.clone(), tool.input_schema.clone())
                .with_description(tool.description.clone())
        })
        .collect()
}

fn durable_agent_id(session_id: &str, turn_id: &str) -> String {
    let mut digest = Sha256::new();
    digest.update(b"zeus-session-agent-v1\0");
    digest.update(
        u64::try_from(session_id.len())
            .expect("validated Session IDs fit in u64")
            .to_be_bytes(),
    );
    digest.update(session_id.as_bytes());
    digest.update(
        u64::try_from(turn_id.len())
            .expect("validated turn IDs fit in u64")
            .to_be_bytes(),
    );
    digest.update(turn_id.as_bytes());
    format!("{:x}", digest.finalize())
}

fn durable_goal_round_identity(
    session_id: &str,
    goal_id: &str,
    goal_revision: u64,
    round: u64,
) -> String {
    let mut digest = Sha256::new();
    digest.update(b"zeus-session-goal-round-v1\0");
    for value in [session_id, goal_id] {
        digest.update(
            u64::try_from(value.len())
                .expect("validated Goal round identifiers fit in u64")
                .to_be_bytes(),
        );
        digest.update(value.as_bytes());
    }
    digest.update(goal_revision.to_be_bytes());
    digest.update(round.to_be_bytes());
    format!("{:x}", digest.finalize())
}

fn kick_followup_worker(state: &ApiState) {
    let Ok(runtime) = tokio::runtime::Handle::try_current() else {
        return;
    };
    let Some(executor) = &state.reply else {
        return;
    };
    if !executor.followup_worker_wake.request() {
        return;
    }
    let state = state.clone();
    runtime.spawn(async move {
        loop {
            if let Err(error) = drain_session_followups(&state).await {
                eprintln!("zeus follow-up worker stopped before admission: {error}");
            }
            let executor = state
                .reply
                .as_ref()
                .expect("a scheduled follow-up worker requires a provider");
            if !executor.followup_worker_wake.complete_cycle() {
                return;
            }
        }
    });
}

async fn drain_session_followups(state: &ApiState) -> Result<(), StoreError> {
    let executor = state
        .reply
        .as_ref()
        .expect("the follow-up worker is only started when a provider exists");
    let _drain = executor.followup_drain.lock().await;
    while let Some(candidate) = state.store.next_session_followup_candidate().await? {
        admit_session_followup(state, executor, candidate).await?;
    }
    Ok(())
}

async fn admit_session_followup(
    state: &ApiState,
    executor: &ReplyExecutor,
    candidate: runtime::SessionFollowupCandidate,
) -> Result<(), StoreError> {
    let user_message = candidate.followup.user_message.clone();
    let default = executor
        .providers
        .default_state(candidate.authz.account_id.clone());
    let selected = state
        .store
        .current_session_reply_provider_for_account(&candidate.authz.account_id, default)
        .await?;
    let provider = executor
        .providers
        .get(&selected.provider_id)
        .ok_or_else(|| {
            StoreError::InvalidAgentTransition(
                "the selected follow-up provider is unavailable".into(),
            )
        })?;
    let metadata = provider.metadata();
    validate_provider_metadata(metadata)
        .map_err(|error| StoreError::InvalidAgentTransition(error.to_string()))?;
    if metadata.provider_id != selected.provider_id
        || metadata.model != selected.model
        || assistant_reply_kind(metadata.reply_kind) != selected.reply_kind
    {
        return Err(StoreError::InvalidAgentTransition(
            "the selected follow-up provider binding changed".into(),
        ));
    }
    let prompt = state
        .store
        .current_session_agent_prompt_for_account(&candidate.authz.account_id)
        .await?;
    validate_agent_initial_content_budget(&prompt.content, &user_message).map_err(|_| {
        StoreError::InvalidAgentTransition(
            "the follow-up exceeds the initial model content budget".into(),
        )
    })?;
    let manifest = state.store.session_agent_manifest_with_prompt(
        &prompt,
        metadata.provider_id.clone(),
        metadata.model.clone(),
        assistant_reply_kind(metadata.reply_kind),
    )?;
    let knowledge = state
        .store
        .current_session_agent_knowledge_context_for_account(
            &candidate.authz.account_id,
            &user_message,
        )
        .await?;
    let checkpoint = state
        .store
        .session_context_checkpoint_for_account(
            &candidate.authz.account_id,
            &candidate.session.id,
            candidate.session.sequence,
        )
        .await?;
    let reply_turns = state
        .store
        .session_reply_turns_after_for_account(
            &candidate.authz.account_id,
            &candidate.session.id,
            checkpoint
                .as_ref()
                .map_or(0, |checkpoint| checkpoint.source_end_sequence),
            candidate.session.sequence,
            AGENT_REQUEST_MAX_HISTORY_PAIRS_WITH_CONTEXT,
        )
        .await?;
    let mut reply_request = ReplyRequest::from_session_history_for_agent_with_optional_system_prompt_checkpoint_and_context(
        &reply_turns,
        user_message,
        Some(prompt.content.as_str()),
        checkpoint
            .as_ref()
            .map(|checkpoint| checkpoint.summary_text.as_str()),
        knowledge.snapshot.snapshot().canonical_context(),
    )
    .map_err(|error| StoreError::InvalidAgentTransition(error.to_string()))?;
    reply_request.tools = agent_tools_from_manifest(&manifest);
    let request_json = persisted_agent_reply_request(&reply_request)
        .map_err(|error| StoreError::InvalidAgentTransition(error.to_string()))?;
    let agent = AgentTurnSpec {
        id: durable_agent_id(&candidate.session.id, &candidate.followup.turn_id),
        authz: candidate.authz.clone(),
        environment: state.store.session_agent_environment().to_owned(),
        provider_name: metadata.provider_id.clone(),
        model_name: metadata.model.clone(),
        request_json,
        manifest,
        knowledge,
    };
    state
        .store
        .start_followup_and_enqueue_agent(candidate, agent)
        .await?;
    kick_agent_model_worker(state);
    Ok(())
}

fn kick_goal_round_worker(state: &ApiState) {
    let Ok(runtime) = tokio::runtime::Handle::try_current() else {
        return;
    };
    let Some(executor) = &state.reply else {
        return;
    };
    if !executor.goal_round_worker_wake.request() {
        return;
    }
    let state = state.clone();
    runtime.spawn(async move {
        loop {
            drain_goal_rounds(&state).await;
            let executor = state
                .reply
                .as_ref()
                .expect("a scheduled Goal round worker requires a provider");
            if !executor.goal_round_worker_wake.complete_cycle() {
                return;
            }
        }
    });
}

async fn drain_goal_rounds(state: &ApiState) {
    let executor = state
        .reply
        .as_ref()
        .expect("the Goal round worker is only started when a provider exists");
    let _drain = executor.goal_round_drain.lock().await;
    for activation in state.store.armed_session_goals().await {
        let candidate = match state.store.agent_goal_round_candidate(&activation).await {
            Ok(Some(candidate)) => candidate,
            Ok(None) => {
                state
                    .store
                    .disarm_session_goal(&activation.session_id)
                    .await;
                continue;
            }
            Err(error) => {
                eprintln!(
                    "zeus disarmed Goal continuation after candidate resolution failed: {error}"
                );
                state
                    .store
                    .disarm_session_goal(&activation.session_id)
                    .await;
                continue;
            }
        };
        if candidate.session.status == SessionStatus::Running
            || candidate.session.active_turn_id.is_some()
        {
            // The same armed Goal may already own an admitted round. Preserve
            // activation until that turn reaches a terminal boundary; its
            // final model completion will wake this worker again.
            continue;
        }
        if let Err(error) = admit_goal_round(state, executor, candidate).await {
            eprintln!("zeus disarmed Goal continuation after round admission failed: {error}");
            state
                .store
                .disarm_session_goal(&activation.session_id)
                .await;
        }
    }
}

async fn admit_goal_round(
    state: &ApiState,
    executor: &ReplyExecutor,
    candidate: runtime::AgentGoalRoundCandidate,
) -> Result<(), StoreError> {
    let (user_message, goal_round): (String, AgentGoalRoundSpec) =
        state.store.prepare_goal_round(&candidate)?;
    let default = executor
        .providers
        .default_state(candidate.authz.account_id.clone());
    let selected = state
        .store
        .current_session_reply_provider_for_account(&candidate.authz.account_id, default)
        .await?;
    let provider = executor
        .providers
        .get(&selected.provider_id)
        .ok_or_else(|| {
            StoreError::InvalidAgentTransition(
                "the selected Goal round provider is unavailable".into(),
            )
        })?;
    let metadata = provider.metadata();
    validate_provider_metadata(metadata)
        .map_err(|error| StoreError::InvalidAgentTransition(error.to_string()))?;
    if metadata.provider_id != selected.provider_id
        || metadata.model != selected.model
        || assistant_reply_kind(metadata.reply_kind) != selected.reply_kind
    {
        return Err(StoreError::InvalidAgentTransition(
            "the selected Goal round provider binding changed".into(),
        ));
    }
    let prompt = state
        .store
        .current_session_agent_prompt_for_account(&candidate.authz.account_id)
        .await?;
    validate_agent_initial_content_budget(&prompt.content, &user_message).map_err(|_| {
        StoreError::InvalidAgentTransition(
            "the Goal round prompt exceeds the initial model content budget".into(),
        )
    })?;
    let manifest = state.store.session_agent_manifest_with_prompt(
        &prompt,
        metadata.provider_id.clone(),
        metadata.model.clone(),
        assistant_reply_kind(metadata.reply_kind),
    )?;
    let knowledge = state
        .store
        .current_session_agent_knowledge_context_for_account(
            &candidate.authz.account_id,
            &user_message,
        )
        .await?;
    let checkpoint = state
        .store
        .session_context_checkpoint_for_account(
            &candidate.authz.account_id,
            &candidate.session.id,
            candidate.session.sequence,
        )
        .await?;
    let reply_turns = state
        .store
        .session_reply_turns_after_for_account(
            &candidate.authz.account_id,
            &candidate.session.id,
            checkpoint
                .as_ref()
                .map_or(0, |checkpoint| checkpoint.source_end_sequence),
            candidate.session.sequence,
            AGENT_REQUEST_MAX_HISTORY_PAIRS_WITH_CONTEXT,
        )
        .await?;
    let mut reply_request = ReplyRequest::from_session_history_for_agent_with_optional_system_prompt_checkpoint_and_context(
        &reply_turns,
        user_message.clone(),
        Some(prompt.content.as_str()),
        checkpoint
            .as_ref()
            .map(|checkpoint| checkpoint.summary_text.as_str()),
        knowledge.snapshot.snapshot().canonical_context(),
    )
    .map_err(|error| StoreError::InvalidAgentTransition(error.to_string()))?;
    reply_request.tools = agent_tools_from_manifest(&manifest);
    let request_json = persisted_agent_reply_request(&reply_request)
        .map_err(|error| StoreError::InvalidAgentTransition(error.to_string()))?;
    let identity = durable_goal_round_identity(
        &candidate.session.id,
        &goal_round.goal_id,
        goal_round.goal_revision,
        goal_round.round,
    );
    let turn_id = format!("goal-round-{identity}");
    let request = StartTurnRequest {
        turn_id: turn_id.clone(),
        user_message,
        expected_sequence: candidate.session.sequence,
    };
    let agent = AgentTurnSpec {
        id: durable_agent_id(&candidate.session.id, &turn_id),
        authz: candidate.authz,
        environment: state.store.session_agent_environment().to_owned(),
        provider_name: metadata.provider_id.clone(),
        model_name: metadata.model.clone(),
        request_json,
        manifest,
        knowledge,
    };
    let admitted = state
        .store
        .start_goal_round_and_enqueue_agent(
            &candidate.session.id,
            request,
            &format!("goal-round-{identity}"),
            agent,
            goal_round,
        )
        .await?;
    if admitted.is_none() {
        return Ok(());
    }
    kick_agent_model_worker(state);
    Ok(())
}

fn kick_compaction_worker(state: &ApiState) {
    let Ok(runtime) = tokio::runtime::Handle::try_current() else {
        return;
    };
    let Some(executor) = &state.reply else {
        return;
    };
    if !executor.compaction_worker_wake.request() {
        return;
    }
    let state = state.clone();
    runtime.spawn(async move {
        loop {
            if let Err(error) =
                retry_agent_durable_progress("compaction worker", || drain_compaction_jobs(&state))
                    .await
            {
                eprintln!("zeus compaction worker stopped on a permanent queue error: {error}");
            }
            let executor = state
                .reply
                .as_ref()
                .expect("a scheduled compaction worker requires a provider");
            if !executor.compaction_worker_wake.complete_cycle() {
                return;
            }
        }
    });
}

async fn drain_compaction_jobs(state: &ApiState) -> Result<(), StoreError> {
    let executor = state
        .reply
        .as_ref()
        .expect("the compaction worker is only started when a provider exists");
    let _drain = executor.compaction_drain.lock().await;
    loop {
        let job = match state.store.claim_next_session_compaction().await? {
            SessionCompactionClaimOutcome::Claimed(job) => *job,
            SessionCompactionClaimOutcome::NotAvailable => return Ok(()),
        };
        process_compaction_job(state, job).await?;
    }
}

async fn process_compaction_job(
    state: &ApiState,
    job: SessionCompactionJob,
) -> Result<(), StoreError> {
    let executor = state
        .reply
        .as_ref()
        .expect("a claimed compaction job requires a provider");
    let Some(provider) = executor.providers.get(&job.provider_name).cloned() else {
        return settle_compaction_failure(
            state,
            &job,
            "provider_configuration_changed",
            "The queued compaction provider is not registered by this Zeus process",
            false,
        )
        .await;
    };
    let metadata = provider.metadata().clone();
    if validate_provider_metadata(&metadata).is_err()
        || !metadata.is_model_reply()
        || job.provider_name != metadata.provider_id
        || metadata.model.as_deref() != Some(job.model_name.as_str())
    {
        return settle_compaction_failure(
            state,
            &job,
            "provider_configuration_changed",
            "The queued compaction no longer matches a model provider",
            false,
        )
        .await;
    }
    let request = match serde_json::from_value::<ReplyRequest>(job.request_json.clone()) {
        Ok(request) if request.tools.is_empty() && validate_reply_request(&request).is_ok() => {
            request
        }
        _ => {
            return settle_compaction_failure(
                state,
                &job,
                "invalid_persisted_request",
                "The persisted compaction request could not be decoded safely",
                false,
            )
            .await;
        }
    };
    let response = match tokio::spawn(async move { provider.reply(request).await }).await {
        Ok(Ok(response)) => response,
        Ok(Err(error)) => {
            let outcome_unknown =
                matches!(error, ProviderError::Timeout | ProviderError::Transport);
            return settle_compaction_failure(
                state,
                &job,
                provider_error_code(&error),
                provider_error_message(&error),
                outcome_unknown,
            )
            .await;
        }
        Err(_) => {
            return settle_compaction_failure(
                state,
                &job,
                "provider_panicked",
                "The compaction provider stopped after its durable start checkpoint",
                true,
            )
            .await;
        }
    };
    if response.provider != metadata {
        return settle_compaction_failure(
            state,
            &job,
            "provider_metadata_mismatch",
            "The compaction provider returned inconsistent provenance",
            false,
        )
        .await;
    }
    let source_bytes = usize::try_from(job.source_content_bytes).map_err(|_| {
        StoreError::ExecutionInvariant("compaction source bytes are not representable".into())
    })?;
    let summary = match validate_compaction_response(&response, source_bytes) {
        Ok(summary) => summary.to_owned(),
        Err(error) => {
            return settle_compaction_failure(
                state,
                &job,
                provider_error_code(&error),
                provider_error_message(&error),
                false,
            )
            .await;
        }
    };
    let response_json = serde_json::to_value(response).map_err(|_| {
        StoreError::ExecutionInvariant("compaction response could not be serialized".into())
    })?;
    state
        .store
        .complete_session_compaction_success(SessionCompactionSuccessCommit {
            job_id: job.id,
            response_json,
            summary_text: summary,
        })
        .await?;
    Ok(())
}

async fn settle_compaction_failure(
    state: &ApiState,
    job: &SessionCompactionJob,
    code: &str,
    message: &str,
    outcome_unknown: bool,
) -> Result<(), StoreError> {
    state
        .store
        .complete_session_compaction_failure(SessionCompactionFailureCommit {
            job_id: job.id.clone(),
            error_json: serde_json::json!({ "code": code, "message": message }),
            outcome_unknown,
        })
        .await?;
    Ok(())
}

fn kick_agent_model_worker(state: &ApiState) {
    let Ok(runtime) = tokio::runtime::Handle::try_current() else {
        return;
    };
    let Some(executor) = &state.reply else {
        return;
    };
    if !executor.agent_model_worker_wake.request() {
        return;
    }
    let state = state.clone();
    runtime.spawn(async move {
        loop {
            if let Err(error) = retry_agent_durable_progress("Agent model worker", || {
                drain_agent_model_jobs(&state)
            })
            .await
            {
                eprintln!("zeus Agent model worker stopped on a permanent queue error: {error}");
            }
            let executor = state
                .reply
                .as_ref()
                .expect("a scheduled Agent model worker requires a provider");
            if !executor.agent_model_worker_wake.complete_cycle() {
                return;
            }
        }
    });
}

async fn drain_agent_model_jobs(state: &ApiState) -> Result<(), StoreError> {
    let executor = state
        .reply
        .as_ref()
        .expect("the Agent model worker is only started when a provider exists");
    let _drain = executor.agent_model_drain.lock().await;
    loop {
        let Some(binding) = state
            .store
            .next_agent_model_for_holder(AGENT_MODEL_WORKER_HOLDER_ID)
            .await?
        else {
            return Ok(());
        };
        // Prompt governance remains live until the start checkpoint, while
        // provider identity comes from the immutable queued job. This lets a
        // selection change affect new turns without rewriting older work.
        let current_manifest = current_agent_manifest(
            &state.store,
            &binding.account_id,
            &binding.provider_name,
            binding.model_name.as_deref(),
            if binding.model_name.is_some() {
                AssistantReplyKind::Model
            } else {
                AssistantReplyKind::NonModelFallback
            },
        )
        .await?;
        let prepared = match state
            .store
            .prepare_next_agent_model(&current_manifest, AGENT_MODEL_WORKER_HOLDER_ID)
            .await?
        {
            AgentModelClaimOutcome::Prepared(prepared) => *prepared,
            AgentModelClaimOutcome::Claimed(_) => {
                return Err(StoreError::ExecutionInvariant(
                    "the Agent model prepare path returned an already-started compatibility claim"
                        .into(),
                ));
            }
            AgentModelClaimOutcome::Rejected(_) => continue,
            AgentModelClaimOutcome::NotAvailable => return Ok(()),
        };
        let cancellation = state
            .store
            .register_agent_model_cancellation(&prepared.job.id);
        let Some(started) =
            retry_prepared_agent_start("Agent model", &prepared.claim.expires_at, || {
                state
                    .store
                    .start_prepared_agent_model(&prepared.claim, &current_manifest)
            })
            .await?
        else {
            continue;
        };
        let job = match started {
            AgentModelStartOutcome::Started(job) => *job,
            AgentModelStartOutcome::Rejected(_) => continue,
        };
        process_agent_model_job(state, job, &current_manifest, cancellation).await?;
    }
}

async fn process_agent_model_job(
    state: &ApiState,
    job: AgentModelJob,
    current_manifest: &ManifestEnvelope,
    cancellation: AgentModelCancellationGuard,
) -> Result<(), StoreError> {
    let executor = state
        .reply
        .as_ref()
        .expect("a claimed Agent model job requires a configured provider");
    let Some(provider) = executor.providers.get(&job.provider_name).cloned() else {
        return settle_agent_model_failure(
            state,
            &job,
            "provider_configuration_changed",
            "The queued Agent provider is not registered by this Zeus process",
            false,
        )
        .await;
    };
    let metadata = provider.metadata().clone();
    if validate_provider_metadata(&metadata).is_err() {
        return settle_agent_model_failure(
            state,
            &job,
            "provider_configuration_invalid",
            "The configured Agent provider is invalid",
            false,
        )
        .await;
    }
    if job.provider_name != metadata.provider_id || job.model_name != metadata.model {
        return settle_agent_model_failure(
            state,
            &job,
            "provider_configuration_changed",
            "The queued Agent step no longer matches the configured provider",
            false,
        )
        .await;
    }

    let request = match serde_json::from_value::<ReplyRequest>(job.request_json.clone()) {
        Ok(request) if validate_agent_reply_request(&request).is_ok() => request,
        _ => {
            return settle_agent_model_failure(
                state,
                &job,
                "invalid_persisted_request",
                "The persisted Agent request could not be decoded safely",
                false,
            )
            .await;
        }
    };
    let current_tools = agent_tools_from_manifest(current_manifest);
    if request.tools != current_tools {
        return settle_agent_model_failure(
            state,
            &job,
            "tool_catalog_changed",
            "The queued Agent step no longer matches the server tool catalog",
            false,
        )
        .await;
    }

    let provider_request = request.clone();
    let output_store = state.store.clone();
    let output_job_id = job.id.clone();
    let response = match tokio::spawn(async move {
        consume_agent_provider_stream(
            output_store,
            output_job_id,
            provider,
            provider_request,
            cancellation,
        )
        .await
    })
    .await
    {
        Ok(Ok(response)) => response,
        Ok(Err(AgentProviderStreamError::Provider(error))) => {
            let outcome_unknown =
                matches!(error, ProviderError::Timeout | ProviderError::Transport);
            return settle_agent_model_failure(
                state,
                &job,
                provider_error_code(&error),
                provider_error_message(&error),
                outcome_unknown,
            )
            .await;
        }
        Ok(Err(AgentProviderStreamError::Durable(error))) => {
            eprintln!("zeus could not persist streamed Agent output: {error}");
            return settle_agent_model_failure(
                state,
                &job,
                "durable_model_output_failed",
                "The Agent output stream could not be persisted after model execution started",
                true,
            )
            .await;
        }
        Ok(Err(AgentProviderStreamError::Cancelled)) => return Ok(()),
        Err(_) => {
            eprintln!("zeus Agent provider task panicked; settling outcome_unknown");
            return settle_agent_model_failure(
                state,
                &job,
                "provider_panicked",
                "The Agent provider stopped after its durable start checkpoint",
                true,
            )
            .await;
        }
    };
    if let Err(error) = validate_agent_reply_response_for_request(&request, &response) {
        return settle_agent_model_failure(
            state,
            &job,
            provider_error_code(&error),
            provider_error_message(&error),
            false,
        )
        .await;
    }
    if response.provider != metadata {
        return settle_agent_model_failure(
            state,
            &job,
            "provider_metadata_mismatch",
            "The Agent provider returned inconsistent provenance",
            false,
        )
        .await;
    }
    let response_json = match serde_json::to_value(&response) {
        Ok(value) => value,
        Err(_) => {
            return settle_agent_model_failure(
                state,
                &job,
                "invalid_provider_response",
                "The Agent provider response could not be persisted safely",
                false,
            )
            .await;
        }
    };

    let resolution = match &response.output {
        ReplyOutput::Final { content } => AgentModelResolution::Final {
            assistant_message: content.clone(),
            provenance: AssistantReplyProvenance {
                provider_id: response.provider.provider_id.clone(),
                model: response.provider.model.clone(),
                reply_kind: match response.provider.reply_kind {
                    ReplyKind::Model => AssistantReplyKind::Model,
                    ReplyKind::NonModelFallback => AssistantReplyKind::NonModelFallback,
                },
            },
        },
        ReplyOutput::ToolCall {
            call: provider_call,
        } => {
            let resolved = match state.store.resolve_session_agent_tool(
                &job.agent_id,
                job.step,
                job.step,
                &provider_call.name,
                provider_call.arguments.clone(),
            ) {
                Ok(resolved) => resolved,
                Err(error) => {
                    eprintln!("zeus rejected a model-selected Agent tool: {error}");
                    return settle_agent_model_failure(
                        state,
                        &job,
                        "tool_resolution_failed",
                        "The model-selected tool could not be resolved safely",
                        false,
                    )
                    .await;
                }
            };
            let resolved_call = resolved.call();
            let evaluation = resolved.policy_evaluation();
            let call = AgentToolCallSpec {
                call_id: resolved_call.call_id.clone(),
                provider_call_id: provider_call.id.clone(),
                tool_name: resolved_call.tool.clone(),
                tool_version: resolved_call.tool_version.clone(),
                arguments_json: resolved_call.arguments.clone(),
                arguments_digest: resolved_call.arguments_digest.clone(),
                effect: resolved_call.effect.clone(),
                sandbox_profile: resolved_call.sandbox_profile.clone(),
                executor_status: resolved_call.executor_status.clone(),
                policy_decision: evaluation.decision.clone(),
                policy_revision: evaluation.policy_revision.clone(),
            };
            if evaluation.decision == PolicyDecision::Deny {
                let result = policy_denied_result(&evaluation.policy_revision);
                AgentModelResolution::PolicyDenied {
                    call,
                    next_request_json: continuation_request_json(&request, provider_call, &result),
                    result_json: result,
                }
            } else {
                AgentModelResolution::ToolCall { call }
            }
        }
    };
    let commit = AgentModelSuccessCommit {
        job_id: job.id.clone(),
        response_json,
        resolution,
    };
    let completion = match retry_agent_durable_progress("Agent model", || {
        state.store.complete_agent_model_success(commit.clone())
    })
    .await
    {
        Ok(completion) => completion,
        Err(error)
            if matches!(
                &commit.resolution,
                AgentModelResolution::PolicyDenied {
                    next_request_json: Some(_),
                    ..
                }
            ) =>
        {
            eprintln!(
                "zeus could not persist an Agent policy-denied continuation; terminalizing the same known denial: {error}"
            );
            let mut fallback = commit;
            if let AgentModelResolution::PolicyDenied {
                next_request_json, ..
            } = &mut fallback.resolution
            {
                *next_request_json = None;
            }
            match retry_agent_durable_progress("Agent policy-denied fallback", || {
                state.store.complete_agent_model_success(fallback.clone())
            })
            .await
            {
                Ok(completion) => completion,
                Err(error) => {
                    eprintln!(
                        "zeus could not persist an Agent policy-denied known-result fallback: {error}"
                    );
                    return settle_agent_model_failure(
                        state,
                        &job,
                        "durable_model_completion_failed",
                        "The model result was known but its durable completion could not be committed",
                        false,
                    )
                    .await;
                }
            }
        }
        Err(error) => {
            eprintln!("zeus could not persist an exact Agent model completion: {error}");
            return settle_agent_model_failure(
                state,
                &job,
                "durable_model_completion_failed",
                "The model result was known but its durable completion could not be committed",
                false,
            )
            .await;
        }
    };
    match completion {
        AgentModelCompletion::ToolCall { call, .. } => match call.status {
            AgentToolCallStatus::Queued => kick_agent_tool_worker(state),
            AgentToolCallStatus::NotDispatched => kick_agent_model_worker(state),
            AgentToolCallStatus::WaitingApproval => {}
            _ => {
                return Err(StoreError::ExecutionInvariant(
                    "a model tool proposal committed an invalid initial call state".into(),
                ));
            }
        },
        AgentModelCompletion::Final(_) => {
            kick_compaction_worker(state);
            kick_followup_worker(state);
            kick_goal_round_worker(state);
        }
        AgentModelCompletion::Terminal(_) => state.store.disarm_session_goal(&job.session_id).await,
    }
    Ok(())
}

const AGENT_OUTPUT_FLUSH_TARGET_BYTES: usize = 256;
const AGENT_OUTPUT_CHUNK_MAX_BYTES: usize = 4 * 1024;

enum AgentProviderStreamError {
    Provider(ProviderError),
    Durable(StoreError),
    Cancelled,
}

impl From<ProviderError> for AgentProviderStreamError {
    fn from(error: ProviderError) -> Self {
        Self::Provider(error)
    }
}

async fn consume_agent_provider_stream(
    store: DemoStore,
    job_id: String,
    provider: Arc<dyn ReplyProvider>,
    request: ReplyRequest,
    cancellation: AgentModelCancellationGuard,
) -> Result<ReplyResponse, AgentProviderStreamError> {
    let mut stream = provider.stream_reply(request);
    let mut buffer = String::new();
    let mut completed = None;
    loop {
        let event = tokio::select! {
            biased;
            _ = cancellation.cancelled() => {
                return Err(AgentProviderStreamError::Cancelled);
            }
            event = stream.next() => event,
        };
        let Some(event) = event else {
            break;
        };
        if completed.is_some() {
            return Err(ProviderError::InvalidResponse.into());
        }
        let event = match event {
            Ok(event) => event,
            Err(error) => {
                persist_agent_output_prefix(&store, &job_id, &mut buffer, true).await?;
                return Err(error.into());
            }
        };
        match event {
            ReplyStreamEvent::TextDelta(delta) => {
                if delta.is_empty() {
                    return Err(ProviderError::InvalidResponse.into());
                }
                buffer.push_str(&delta);
                while buffer.len() >= AGENT_OUTPUT_FLUSH_TARGET_BYTES {
                    persist_agent_output_prefix(&store, &job_id, &mut buffer, false).await?;
                }
            }
            ReplyStreamEvent::Completed(response) => {
                if completed.replace(response).is_some() {
                    return Err(ProviderError::InvalidResponse.into());
                }
                persist_agent_output_prefix(&store, &job_id, &mut buffer, true).await?;
            }
        }
    }
    match completed {
        Some(response) => Ok(response),
        None => {
            persist_agent_output_prefix(&store, &job_id, &mut buffer, true).await?;
            Err(ProviderError::InvalidResponse.into())
        }
    }
}

async fn persist_agent_output_prefix(
    store: &DemoStore,
    job_id: &str,
    buffer: &mut String,
    flush_all: bool,
) -> Result<(), AgentProviderStreamError> {
    while !buffer.is_empty() && (flush_all || buffer.len() >= AGENT_OUTPUT_FLUSH_TARGET_BYTES) {
        let target = if flush_all {
            buffer.len().min(AGENT_OUTPUT_CHUNK_MAX_BYTES)
        } else {
            AGENT_OUTPUT_FLUSH_TARGET_BYTES.min(AGENT_OUTPUT_CHUNK_MAX_BYTES)
        };
        let mut end = target;
        while end > 0 && !buffer.is_char_boundary(end) {
            end -= 1;
        }
        if end == 0 {
            return Err(ProviderError::InvalidResponse.into());
        }
        let remainder = buffer.split_off(end);
        let content = std::mem::replace(buffer, remainder);
        store
            .append_agent_model_output_chunk(job_id, content)
            .await
            .map_err(AgentProviderStreamError::Durable)?;
    }
    Ok(())
}

async fn settle_agent_model_failure(
    state: &ApiState,
    job: &AgentModelJob,
    code: &str,
    message: &str,
    outcome_unknown: bool,
) -> Result<(), StoreError> {
    let commit = AgentModelFailureCommit {
        job_id: job.id.clone(),
        error_json: serde_json::json!({ "code": code, "message": message }),
        outcome_unknown,
    };
    retry_agent_durable_progress("Agent model failure", || {
        state.store.complete_agent_model_failure(commit.clone())
    })
    .await?;
    state.store.disarm_session_goal(&job.session_id).await;
    Ok(())
}

fn kick_agent_tool_worker(state: &ApiState) {
    let Ok(runtime) = tokio::runtime::Handle::try_current() else {
        return;
    };
    let Some(executor) = &state.reply else {
        return;
    };
    if !executor.agent_tool_worker_wake.request() {
        return;
    }
    let state = state.clone();
    runtime.spawn(async move {
        loop {
            if let Err(error) =
                retry_agent_durable_progress("Agent tool worker", || drain_agent_tool_calls(&state))
                    .await
            {
                eprintln!("zeus Agent tool worker stopped on a permanent queue error: {error}");
            }
            let executor = state
                .reply
                .as_ref()
                .expect("a scheduled Agent tool worker requires a provider");
            if !executor.agent_tool_worker_wake.complete_cycle() {
                return;
            }
        }
    });
}

async fn drain_agent_tool_calls(state: &ApiState) -> Result<(), StoreError> {
    let executor = state
        .reply
        .as_ref()
        .expect("the Agent tool worker is only started when a provider exists");
    let _drain = executor.agent_tool_drain.lock().await;
    loop {
        let Some(binding) = state
            .store
            .next_agent_tool_for_holder(AGENT_TOOL_WORKER_HOLDER_ID)
            .await?
        else {
            return Ok(());
        };
        let model_job = &binding.model_job;
        let current_manifest = current_agent_manifest(
            &state.store,
            &model_job.account_id,
            &model_job.provider_name,
            model_job.model_name.as_deref(),
            if model_job.model_name.is_some() {
                AssistantReplyKind::Model
            } else {
                AssistantReplyKind::NonModelFallback
            },
        )
        .await?;
        let prepared = match state
            .store
            .prepare_next_agent_tool(&current_manifest, AGENT_TOOL_WORKER_HOLDER_ID)
            .await?
        {
            AgentToolClaimOutcome::Prepared(prepared) => *prepared,
            AgentToolClaimOutcome::Claimed(_) => {
                return Err(StoreError::ExecutionInvariant(
                    "the Agent tool prepare path returned an already-started compatibility claim"
                        .into(),
                ));
            }
            AgentToolClaimOutcome::Rejected(_) => continue,
            AgentToolClaimOutcome::NotAvailable => return Ok(()),
        };
        let Some(started) =
            retry_prepared_agent_start("Agent tool", &prepared.claim.expires_at, || {
                state
                    .store
                    .start_prepared_agent_tool(&prepared.claim, &current_manifest)
            })
            .await?
        else {
            continue;
        };
        let work = match started {
            AgentToolStartOutcome::Started(work) => *work,
            AgentToolStartOutcome::Rejected(_) => continue,
        };
        process_agent_tool_work(state, work).await?;
    }
}

async fn process_agent_tool_work(state: &ApiState, work: AgentToolWork) -> Result<(), StoreError> {
    let scoped = match state.store.verify_persisted_session_agent_tool_work(&work) {
        Ok(resolved) => resolved,
        Err(error) => {
            eprintln!("zeus refused a drifted persisted Agent tool: {error}");
            return settle_known_agent_tool(
                state,
                &work,
                AgentToolCallStatus::NotDispatched,
                serde_json::json!({
                    "code": "tool_contract_changed",
                    "message": "The persisted tool no longer matches the current runtime",
                    "status": "not_dispatched"
                }),
                None,
                None,
            )
            .await;
        }
    };
    let approval = approval_for_agent_call(&work.call);
    let store = state.store.clone();
    let outcome = tokio::spawn(async move {
        store
            .dispatch_session_agent_tool_after_checkpoint(scoped, approval.as_ref())
            .await
    })
    .await;
    match outcome {
        Ok(Ok(output)) => {
            let subagent_spawn = if work.call.tool_name == subagents::SPAWN_AGENT_TOOL_NAME
                && work.call.tool_version == subagents::SPAWN_AGENT_TOOL_VERSION
            {
                match prepare_agent_subagent_spawn(state, &work).await {
                    Ok(spawn) => Some(spawn),
                    Err(error) => {
                        eprintln!("zeus rejected spawn_agent before child admission: {error}");
                        return settle_known_agent_tool(
                            state,
                            &work,
                            AgentToolCallStatus::Failed,
                            serde_json::json!({
                                "code": "subagent_admission_failed",
                                "message": "The child Agent could not be safely admitted",
                                "retryable": false,
                                "status": "failed"
                            }),
                            None,
                            None,
                        )
                        .await;
                    }
                }
            } else {
                None
            };
            settle_known_agent_tool(
                state,
                &work,
                AgentToolCallStatus::Succeeded,
                output.value,
                output.provider_request_id,
                subagent_spawn,
            )
            .await
        }
        Ok(Err(error)) if error.is_executor_outcome_unknown() => {
            eprintln!("zeus Agent tool executor reported outcome_unknown");
            settle_agent_tool_outcome_unknown(
                state,
                &work.call,
                "executor_outcome_unknown",
                "The executor could not determine the outcome after the durable start checkpoint",
            )
            .await
        }
        Ok(Err(error)) => {
            eprintln!("zeus Agent tool returned a known failure: {error}");
            let (status, result) = if let Some((code, message, retryable)) =
                error.known_executor_failure()
            {
                (
                    AgentToolCallStatus::Failed,
                    serde_json::json!({
                        "code": code,
                        "message": message,
                        "retryable": retryable,
                        "status": "failed"
                    }),
                )
            } else {
                match error {
                    StoreError::PolicyDenied(_) | StoreError::PolicyChanged(_) => (
                        AgentToolCallStatus::NotDispatched,
                        serde_json::json!({
                            "code": "tool_not_dispatched",
                            "message": "The tool was not dispatched because its execution contract changed",
                            "status": "not_dispatched"
                        }),
                    ),
                    _ => (
                        AgentToolCallStatus::Failed,
                        serde_json::json!({
                            "code": "tool_execution_failed",
                            "message": "The tool returned a known failure",
                            "status": "failed"
                        }),
                    ),
                }
            };
            settle_known_agent_tool(state, &work, status, result, None, None).await
        }
        Err(_) => {
            eprintln!("zeus Agent tool task panicked; settling outcome_unknown");
            settle_agent_tool_outcome_unknown(
                state,
                &work.call,
                "tool_panicked",
                "The tool stopped after its durable start checkpoint",
            )
            .await
        }
    }
}

async fn settle_known_agent_tool(
    state: &ApiState,
    work: &AgentToolWork,
    status: AgentToolCallStatus,
    result_json: serde_json::Value,
    provider_request_id: Option<String>,
    subagent_spawn: Option<AgentSubagentSpawnCommit>,
) -> Result<(), StoreError> {
    let mut committed_status = status.clone();
    let mut committed_result = result_json.clone();
    let next_request_json = continuation_request_json_for_work(work, &result_json);
    let commit = AgentToolCompletionCommit {
        call_id: work.call.call_id.clone(),
        status,
        result_json,
        provider_request_id,
        next_request_json,
    };
    let complete = |commit: AgentToolCompletionCommit| {
        let subagent_spawn = subagent_spawn.clone();
        async move {
            match subagent_spawn {
                Some(spawn) => {
                    state
                        .store
                        .complete_agent_tool_with_subagent(commit, spawn)
                        .await
                }
                None => state.store.complete_agent_tool(commit).await,
            }
        }
    };
    let completion = match retry_agent_durable_progress("Agent tool", || complete(commit.clone()))
        .await
    {
        Ok(completion) => completion,
        Err(StoreError::SubagentAdmissionRejected) if subagent_spawn.is_some() => {
            committed_status = AgentToolCallStatus::Failed;
            committed_result = serde_json::json!({
                "code": "subagent_capacity_exceeded",
                "message": "The bounded child Agent capacity is exhausted",
                "retryable": false,
                "status": "failed"
            });
            let failed = AgentToolCompletionCommit {
                call_id: work.call.call_id.clone(),
                status: committed_status.clone(),
                result_json: committed_result.clone(),
                provider_request_id: None,
                next_request_json: continuation_request_json_for_work(work, &committed_result),
            };
            retry_agent_durable_progress("Agent subagent rejection", || {
                state.store.complete_agent_tool(failed.clone())
            })
            .await?
        }
        Err(error) if commit.next_request_json.is_some() => {
            eprintln!(
                "zeus could not persist an Agent tool continuation; terminalizing the same known result: {error}"
            );
            let mut fallback = commit;
            fallback.next_request_json = None;
            retry_agent_durable_progress("Agent tool known-result fallback", || {
                complete(fallback.clone())
            })
            .await?
        }
        Err(error) => return Err(error),
    };
    if committed_status == AgentToolCallStatus::Succeeded {
        state
            .store
            .apply_committed_goal_tool_result(work, &committed_result)
            .await?;
    }
    if subagent_spawn.is_some() && committed_status == AgentToolCallStatus::Succeeded {
        kick_agent_model_worker(state);
    }
    if matches!(completion, AgentToolCompletion::ModelQueued { .. }) {
        kick_agent_model_worker(state);
    } else {
        state.store.disarm_session_goal(&work.call.session_id).await;
    }
    Ok(())
}

async fn settle_agent_tool_outcome_unknown(
    state: &ApiState,
    call: &AgentToolCall,
    code: &str,
    message: &str,
) -> Result<(), StoreError> {
    let commit = AgentToolOutcomeUnknownCommit {
        call_id: call.call_id.clone(),
        error_json: serde_json::json!({ "code": code, "message": message }),
    };
    retry_agent_durable_progress("Agent tool outcome-unknown", || {
        state
            .store
            .complete_agent_tool_outcome_unknown(commit.clone())
    })
    .await?;
    state.store.disarm_session_goal(&call.session_id).await;
    Ok(())
}

fn approval_for_agent_call(call: &AgentToolCall) -> Option<Approval> {
    (call.policy_decision == PolicyDecision::RequireApproval).then(|| Approval {
        id: call.call_id.clone(),
        status: ApprovalStatus::Approved,
        action: "execute the approved Agent tool".into(),
        tool: call.tool_name.clone(),
        change: "execute the exact persisted tool call".into(),
        requires_approval: true,
        call_id: Some(call.call_id.clone()),
        policy_revision: Some(call.policy_revision.clone()),
        arguments_digest: Some(call.arguments_digest.clone()),
        sandbox_profile: Some(call.sandbox_profile.clone()),
        scope: Some(ApprovalScope::AllowOnce),
    })
}

fn continuation_request_for_work(
    work: &AgentToolWork,
    result: &serde_json::Value,
) -> Result<ReplyRequest, ProviderError> {
    let request = serde_json::from_value::<ReplyRequest>(work.model_job.request_json.clone())
        .map_err(|_| ProviderError::InvalidRequest("invalid persisted Agent request"))?;
    validate_agent_reply_request(&request)?;
    let response_json = work
        .model_job
        .response_json
        .clone()
        .ok_or(ProviderError::InvalidResponse)?;
    let response = serde_json::from_value::<llm::ReplyResponse>(response_json)
        .map_err(|_| ProviderError::InvalidResponse)?;
    validate_agent_reply_response_for_request(&request, &response)?;
    let ReplyOutput::ToolCall { call } = response.output else {
        return Err(ProviderError::InvalidResponse);
    };
    if call.id != work.call.provider_call_id
        || call.name != work.call.tool_name
        || call.arguments != work.call.arguments_json
    {
        return Err(ProviderError::InvalidResponse);
    }
    continuation_request(&request, &call, result)
}

fn continuation_request_json_for_work(
    work: &AgentToolWork,
    result: &serde_json::Value,
) -> Option<serde_json::Value> {
    let next = match continuation_request_for_work(work, result) {
        Ok(next) => next,
        Err(error) => {
            eprintln!("zeus could not build a bounded Agent continuation: {error}");
            return None;
        }
    };
    match persisted_agent_reply_request(&next) {
        Ok(next) => Some(next),
        Err(error) => {
            eprintln!("zeus could not serialize a validated Agent continuation: {error}");
            None
        }
    }
}

fn continuation_request_json(
    request: &ReplyRequest,
    call: &ReplyToolCall,
    result: &serde_json::Value,
) -> Option<serde_json::Value> {
    let next = match continuation_request(request, call, result) {
        Ok(next) => next,
        Err(error) => {
            eprintln!("zeus could not build a bounded Agent continuation: {error}");
            return None;
        }
    };
    match persisted_agent_reply_request(&next) {
        Ok(next) => Some(next),
        Err(error) => {
            eprintln!("zeus could not serialize a validated Agent continuation: {error}");
            None
        }
    }
}

fn continuation_request(
    request: &ReplyRequest,
    call: &ReplyToolCall,
    result: &serde_json::Value,
) -> Result<ReplyRequest, ProviderError> {
    let content = serde_json::to_string(result).map_err(|_| ProviderError::InvalidResponse)?;
    agent_continuation_request(request, call, content)
}

fn policy_denied_result(policy_revision: &str) -> serde_json::Value {
    serde_json::json!({
        "code": "policy_denied",
        "message": "Zeus policy denied this tool call",
        "policy_revision": policy_revision,
        "status": "not_dispatched"
    })
}

async fn overview(
    State(state): State<ApiState>,
    Extension(current): Extension<CurrentAuth>,
) -> Result<Json<protocol::OverviewResponse>, ApiError> {
    Ok(Json(
        state
            .store
            .overview_for_actor(&current.principal.authz)
            .await?,
    ))
}

async fn list_sessions(
    State(state): State<ApiState>,
    Extension(current): Extension<CurrentAuth>,
    query: Result<Query<SessionListQuery>, QueryRejection>,
) -> Result<Response, ApiError> {
    let Query(query) = query.map_err(ApiError::invalid_query)?;
    let page = state
        .store
        .list_sessions_for_actor(
            &current.principal.authz,
            query.cursor.as_deref(),
            query.limit.unwrap_or(COLLECTION_PAGE_DEFAULT_LIMIT),
        )
        .await?;
    let mut headers = HeaderMap::new();
    if let Some(cursor) = page.next_cursor {
        headers.insert(
            "x-zeus-next-cursor",
            HeaderValue::from_str(&cursor).expect("opaque cursor is canonical base64url"),
        );
    }
    Ok((headers, Json(page.items)).into_response())
}

async fn create_session(
    State(state): State<ApiState>,
    Extension(current): Extension<CurrentAuth>,
    headers: HeaderMap,
    payload: Result<Json<CreateSessionRequest>, JsonRejection>,
) -> Result<(StatusCode, Json<CreateSessionResponse>), ApiError> {
    let Json(request) = payload.map_err(ApiError::invalid_json)?;
    let idempotency_key = required_idempotency_key(&headers)?;
    let response = state
        .store
        .create_session_for_actor(&current.principal.authz, request, &idempotency_key)
        .await?;
    Ok((StatusCode::CREATED, Json(response)))
}

async fn fork_session(
    State(state): State<ApiState>,
    Extension(current): Extension<CurrentAuth>,
    Path(parent_session_id): Path<String>,
    headers: HeaderMap,
    payload: Result<Json<ForkSessionRequest>, JsonRejection>,
) -> Result<(StatusCode, Json<ForkSessionResponse>), ApiError> {
    let Json(request) = payload.map_err(ApiError::invalid_json)?;
    let idempotency_key = required_idempotency_key(&headers)?;
    let response = state
        .store
        .fork_session_for_actor(
            &current.principal.authz,
            &parent_session_id,
            request,
            &idempotency_key,
        )
        .await?;
    let status = if response.replayed {
        StatusCode::OK
    } else {
        StatusCode::CREATED
    };
    Ok((status, Json(response)))
}

async fn list_session_forks(
    State(state): State<ApiState>,
    Extension(current): Extension<CurrentAuth>,
    Path(parent_session_id): Path<String>,
    query: Result<Query<SessionForkListQuery>, QueryRejection>,
) -> Result<Response, ApiError> {
    state
        .store
        .authorize_session_for_actor(&current.principal.authz, &parent_session_id)
        .await?;
    let Query(query) = query.map_err(ApiError::invalid_query)?;
    let page = state
        .store
        .list_session_forks_for_actor(
            &current.principal.authz,
            &parent_session_id,
            query.cursor.as_deref(),
            query.limit.unwrap_or(COLLECTION_PAGE_DEFAULT_LIMIT),
        )
        .await?;
    let mut headers = HeaderMap::new();
    if let Some(cursor) = page.next_cursor {
        headers.insert(
            "x-zeus-next-cursor",
            HeaderValue::from_str(&cursor).expect("opaque cursor is canonical base64url"),
        );
    }
    Ok((headers, Json(page.items)).into_response())
}

async fn session_detail(
    State(state): State<ApiState>,
    Extension(current): Extension<CurrentAuth>,
    Path(id): Path<String>,
    query: Result<Query<SessionDetailQuery>, QueryRejection>,
) -> Result<Json<SessionDetail>, ApiError> {
    state
        .store
        .authorize_session_for_actor(&current.principal.authz, &id)
        .await?;
    let Query(query) = query.map_err(ApiError::invalid_query)?;
    Ok(Json(
        state
            .store
            .get_session_for_actor(
                &current.principal.authz,
                &id,
                query.run_ids_before.as_deref(),
                query.run_ids_limit.unwrap_or(COLLECTION_PAGE_DEFAULT_LIMIT),
                query.turns_before.as_deref(),
                query.turns_limit.unwrap_or(COLLECTION_PAGE_DEFAULT_LIMIT),
                query.events_before.as_deref(),
                query.events_limit.unwrap_or(EVENT_PAGE_DEFAULT_LIMIT),
            )
            .await?,
    ))
}

async fn session_turn(
    State(state): State<ApiState>,
    Extension(current): Extension<CurrentAuth>,
    Path((id, turn_id)): Path<(String, String)>,
) -> Result<Json<SessionTurn>, ApiError> {
    state
        .store
        .authorize_session_for_actor(&current.principal.authz, &id)
        .await?;
    Ok(Json(
        state
            .store
            .session_turn_for_actor(&current.principal.authz, &id, &turn_id)
            .await?,
    ))
}

async fn agent_turn_detail(
    State(state): State<ApiState>,
    Extension(current): Extension<CurrentAuth>,
    Path((id, turn_id)): Path<(String, String)>,
) -> Result<Json<AgentTurnDetail>, ApiError> {
    Ok(Json(
        state
            .store
            .agent_turn_detail_for_actor(&current.principal.authz, &id, &turn_id)
            .await?,
    ))
}

async fn agent_output_chunks(
    State(state): State<ApiState>,
    Extension(current): Extension<CurrentAuth>,
    Path((id, turn_id)): Path<(String, String)>,
    query: Result<Query<AgentOutputQuery>, QueryRejection>,
) -> Result<Response, ApiError> {
    state
        .store
        .authorize_session_for_actor(&current.principal.authz, &id)
        .await?;
    let Query(query) = query.map_err(ApiError::invalid_query)?;
    let page = state
        .store
        .agent_output_chunk_page_for_actor(
            &current.principal.authz,
            &id,
            &turn_id,
            query.after.unwrap_or(0),
            query.limit.unwrap_or(EVENT_PAGE_DEFAULT_LIMIT),
        )
        .await?;
    json_no_store(page)
}

async fn agent_output_events(
    State(state): State<ApiState>,
    Extension(current): Extension<CurrentAuth>,
    Path((id, turn_id)): Path<(String, String)>,
    headers: HeaderMap,
    query: Result<Query<EventsQuery>, QueryRejection>,
) -> Result<Response, ApiError> {
    state
        .store
        .authorize_session_for_actor(&current.principal.authz, &id)
        .await?;
    let Query(query) = query.map_err(ApiError::invalid_query)?;
    let after = event_cursor(&headers, query)?;
    if !sse_auth_is_current(&state.store, &current).await {
        return Err(ApiError::unauthorized());
    }
    let authz = current.principal.authz.clone();
    let sse_lease = acquire_sse_lease(&state.sse_capacity, &authz)?;
    let first = state
        .store
        .agent_output_chunk_page_for_actor(
            &authz,
            &id,
            &turn_id,
            after,
            protocol::EVENT_PAGE_DEFAULT_LIMIT,
        )
        .await?;
    let store = state.store.clone();
    let poll_interval = state.durable_ledger_poll_interval;
    let session_id = id;

    let stream = async_stream::stream! {
        let _sse_lease = sse_lease;
        let mut cursor = after;
        let mut page = first;
        let mut stream_opened = false;
        loop {
            for chunk in page.items.drain(..) {
                if chunk.sequence <= cursor {
                    eprintln!("zeus Agent output SSE page did not advance its durable cursor");
                    return;
                }
                cursor = chunk.sequence;
                yield Ok::<Event, Infallible>(agent_output_sse_event(&chunk));
            }
            if page.has_more {
                match store
                    .agent_output_chunk_page_for_actor(
                        &authz,
                        &session_id,
                        &turn_id,
                        cursor,
                        protocol::EVENT_PAGE_DEFAULT_LIMIT,
                    )
                    .await
                {
                    Ok(next) if !next.items.is_empty() => {
                        page = next;
                        continue;
                    }
                    Ok(_) => {
                        eprintln!("zeus Agent output SSE page reported more data without progress");
                        return;
                    }
                    Err(error) => {
                        eprintln!("zeus Agent output SSE replay failed: {error:?}");
                        return;
                    }
                }
            }
            if page.terminal && cursor == page.head_sequence {
                return;
            }
            if !stream_opened {
                yield Ok(Event::default().comment("stream-open"));
                stream_opened = true;
            }
            tokio::time::sleep(poll_interval).await;
            if !sse_auth_is_current(&store, &current).await {
                return;
            }
            match store
                .agent_output_chunk_page_for_actor(
                    &authz,
                    &session_id,
                    &turn_id,
                    cursor,
                    protocol::EVENT_PAGE_DEFAULT_LIMIT,
                )
                .await
            {
                Ok(next) => page = next,
                Err(error) => {
                    eprintln!("zeus Agent output SSE durable poll failed: {error:?}");
                    return;
                }
            }
        }
    };

    let mut response = Sse::new(stream)
        .keep_alive(
            KeepAlive::new()
                .interval(Duration::from_secs(15))
                .text("keep-alive"),
        )
        .into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    Ok(response)
}

fn agent_output_sse_event(chunk: &protocol::AgentOutputChunk) -> Event {
    Event::default()
        .event("agent.output")
        .id(chunk.sequence.to_string())
        .data(serde_json::to_string(chunk).expect("AgentOutputChunk must serialize"))
}

async fn cancel_agent_turn(
    State(state): State<ApiState>,
    Extension(current): Extension<CurrentAuth>,
    Path((id, turn_id)): Path<(String, String)>,
    payload: Result<Json<CancelAgentTurnRequest>, JsonRejection>,
) -> Result<Response, ApiError> {
    let Json(request) = payload
        .map_err(ApiError::invalid_json)
        .map_err(ApiError::with_no_store)?;
    if request.expected_revision == 0 {
        return Err(ApiError::bad_request(
            "invalid_agent_revision",
            "Agent revision must be a positive integer",
        )
        .with_no_store());
    }
    let response: CancelAgentTurnResponse = state
        .store
        .cancel_agent_turn_for_actor(
            &current.principal.authz,
            &id,
            &turn_id,
            request.expected_revision,
        )
        .await
        .map_err(ApiError::from)
        .map_err(ApiError::with_no_store)?;
    json_no_store(response)
}

async fn agent_deployment_explain(
    State(state): State<ApiState>,
    Extension(current): Extension<CurrentAuth>,
    Path((id, turn_id)): Path<(String, String)>,
) -> Result<Response, ApiError> {
    let agent = state
        .store
        .agent_turn_detail_for_actor(&current.principal.authz, &id, &turn_id)
        .await
        .map_err(ApiError::from)
        .map_err(ApiError::with_no_store)?;
    let persisted_manifest = state
        .store
        .agent_deployment_manifest_for_actor(&current.principal.authz, &id, &turn_id)
        .await
        .map_err(ApiError::from)
        .map_err(ApiError::with_no_store)?;
    let executor = reply_executor(&state).map_err(ApiError::with_no_store)?;
    let selected =
        selected_provider_for_actor(&state.store, executor, &current.principal.authz).await?;
    let provider = provider_for_state(executor, &selected)?;
    let metadata = provider.metadata();
    let current_manifest = current_agent_manifest(
        &state.store,
        &current.principal.authz.account_id,
        &metadata.provider_id,
        metadata.model.as_deref(),
        assistant_reply_kind(metadata.reply_kind),
    )
    .await
    .map_err(ApiError::from)
    .map_err(ApiError::with_no_store)?;
    let legacy_unbound = persisted_manifest.is_none();
    let matches_current = persisted_manifest
        .as_ref()
        .is_some_and(|persisted| persisted.digest == current_manifest.digest);
    let diff = persisted_manifest
        .as_ref()
        .filter(|persisted| persisted.digest != current_manifest.digest)
        .map(|persisted| persisted.manifest.diff(&current_manifest.manifest))
        .transpose()
        .map_err(|error| ApiError::internal_contract(&error.to_string()))?;

    json_no_store(AgentDeploymentExplainResponse {
        agent,
        persisted_manifest,
        current_manifest,
        legacy_unbound,
        matches_current,
        diff,
    })
}

async fn agent_execution_explain(
    State(state): State<ApiState>,
    Extension(current): Extension<CurrentAuth>,
    Path((id, turn_id)): Path<(String, String)>,
) -> Result<Response, ApiError> {
    let explanation: AgentExecutionExplain = state
        .store
        .agent_execution_explain_for_actor(&current.principal.authz, &id, &turn_id)
        .await
        .map_err(ApiError::from)
        .map_err(ApiError::with_no_store)?;
    json_no_store(explanation)
}

async fn agent_knowledge_explain(
    State(state): State<ApiState>,
    Extension(current): Extension<CurrentAuth>,
    Path((id, turn_id)): Path<(String, String)>,
) -> Result<Response, ApiError> {
    let agent = state
        .store
        .agent_turn_detail_for_actor(&current.principal.authz, &id, &turn_id)
        .await
        .map_err(ApiError::from)
        .map_err(ApiError::with_no_store)?;
    let context = state
        .store
        .agent_knowledge_context_for_actor(&current.principal.authz, &id, &turn_id)
        .await
        .map_err(ApiError::from)
        .map_err(ApiError::with_no_store)?;
    json_no_store(AgentKnowledgeExplainResponse {
        agent,
        legacy_unbound: context.is_none(),
        context,
    })
}

async fn agent_run_epoch_explain(
    State(state): State<ApiState>,
    Extension(current): Extension<CurrentAuth>,
    Path((id, turn_id, step)): Path<(String, String, String)>,
) -> Result<Response, ApiError> {
    // Resolve account authority before reporting path-specific validation so a
    // foreign Session remains indistinguishable from a missing Session.
    state
        .store
        .authorize_session_for_actor(&current.principal.authz, &id)
        .await
        .map_err(ApiError::from)
        .map_err(ApiError::with_no_store)?;
    let step = step
        .parse::<u32>()
        .ok()
        .filter(|step| *step > 0)
        .ok_or_else(|| {
            ApiError::bad_request(
                "invalid_agent_epoch_step",
                "Agent model step must be a positive integer",
            )
            .with_no_store()
        })?;
    let explanation: AgentRunEpochExplain = state
        .store
        .agent_run_epoch_explain_for_actor(&current.principal.authz, &id, &turn_id, step)
        .await
        .map_err(ApiError::from)
        .map_err(ApiError::with_no_store)?;
    json_no_store(explanation)
}

async fn resume_session(
    State(state): State<ApiState>,
    Extension(current): Extension<CurrentAuth>,
    Path(id): Path<String>,
    headers: HeaderMap,
    payload: Result<Json<ResumeSessionRequest>, JsonRejection>,
) -> Result<Json<ResumeSessionResponse>, ApiError> {
    state
        .store
        .authorize_session_for_actor(&current.principal.authz, &id)
        .await?;
    let Json(request) = payload.map_err(ApiError::invalid_json)?;
    let idempotency_key = required_idempotency_key(&headers)?;
    let response = state
        .store
        .resume_session_for_actor(&current.principal.authz, &id, request, &idempotency_key)
        .await?;
    kick_followup_worker(&state);
    Ok(Json(response))
}

async fn flush_session(
    State(state): State<ApiState>,
    Extension(current): Extension<CurrentAuth>,
    Path(id): Path<String>,
    query: Result<Query<SessionFlushQuery>, QueryRejection>,
) -> Result<Response, ApiError> {
    // Resolve actor authority before parsing barrier-specific input so a
    // foreign Session is indistinguishable from a missing Session.
    state
        .store
        .authorize_session_for_actor(&current.principal.authz, &id)
        .await?;
    let Query(query) = query.map_err(ApiError::invalid_query)?;
    let timeout = query
        .timeout_ms
        .map(Duration::from_millis)
        .unwrap_or(SESSION_FLUSH_DEFAULT_TIMEOUT);
    if timeout > SESSION_FLUSH_MAX_TIMEOUT {
        return Err(ApiError::bad_request(
            "invalid_session_flush_timeout",
            format!(
                "Session flush timeout must be between 0 and {} milliseconds",
                SESSION_FLUSH_MAX_TIMEOUT.as_millis()
            ),
        )
        .with_no_store());
    }

    let mut barrier = state
        .store
        .capture_session_flush_barrier_for_actor(&current.principal.authz, &id)
        .await?;
    kick_agent_model_worker(&state);
    kick_followup_worker(&state);
    let deadline = Instant::now() + timeout;
    while barrier.status == SessionFlushBarrierStatus::Pending {
        let now = Instant::now();
        if now >= deadline {
            break;
        }
        tokio::time::sleep_until((now + SESSION_FLUSH_POLL_INTERVAL).min(deadline)).await;
        barrier = state
            .store
            .observe_session_flush_barrier_for_actor(&current.principal.authz, barrier)
            .await?;
    }
    Ok(session_flush_response(barrier))
}

fn session_flush_response(barrier: SessionFlushBarrier) -> Response {
    let pending = barrier.status == SessionFlushBarrierStatus::Pending;
    let mut response = Json(barrier).into_response();
    if pending {
        *response.status_mut() = StatusCode::ACCEPTED;
        response
            .headers_mut()
            .insert(header::RETRY_AFTER, HeaderValue::from_static("1"));
    }
    no_store(response.headers_mut());
    response
}

async fn list_session_followups(
    State(state): State<ApiState>,
    Extension(current): Extension<CurrentAuth>,
    Path(id): Path<String>,
) -> Result<Json<SessionFollowupListResponse>, ApiError> {
    let items = state
        .store
        .session_followups_for_actor(&current.principal.authz, &id)
        .await?;
    Ok(Json(SessionFollowupListResponse { items }))
}

async fn enqueue_session_followup(
    State(state): State<ApiState>,
    Extension(current): Extension<CurrentAuth>,
    Path(id): Path<String>,
    headers: HeaderMap,
    payload: Result<Json<EnqueueSessionFollowupRequest>, JsonRejection>,
) -> Result<(StatusCode, Json<EnqueueSessionFollowupResponse>), ApiError> {
    state
        .store
        .authorize_session_for_actor(&current.principal.authz, &id)
        .await?;
    let Json(request) = payload.map_err(ApiError::invalid_json)?;
    let idempotency_key = required_idempotency_key(&headers)?;
    let response = state
        .store
        .enqueue_session_followup_for_actor(
            &current.principal.authz,
            &id,
            request,
            &idempotency_key,
        )
        .await?;
    kick_followup_worker(&state);
    Ok((StatusCode::ACCEPTED, Json(response)))
}

async fn start_turn(
    State(state): State<ApiState>,
    Extension(current): Extension<CurrentAuth>,
    Path(id): Path<String>,
    headers: HeaderMap,
    payload: Result<Json<StartTurnRequest>, JsonRejection>,
) -> Result<Response, ApiError> {
    state
        .store
        .authorize_session_for_actor(&current.principal.authz, &id)
        .await?;
    // A direct, authorized human turn always wins over process-local automatic
    // continuation, including while its request context is still being built.
    state.store.disarm_session_goal(&id).await;
    let Json(request) = payload.map_err(ApiError::invalid_json)?;
    let idempotency_key = required_idempotency_key(&headers)?;
    validate_start_turn_envelope(&request)?;
    let prompt = state
        .store
        .session_agent_prompt_for_actor(&current.principal.authz)
        .await?;
    validate_agent_initial_content_budget(&prompt.content, &request.user_message)?;
    let executor = reply_executor(&state)?;
    let selected =
        selected_provider_for_actor(&state.store, executor, &current.principal.authz).await?;
    let metadata = provider_for_state(executor, &selected)?.metadata();
    let manifest = state.store.session_agent_manifest_with_prompt(
        &prompt,
        metadata.provider_id.clone(),
        metadata.model.clone(),
        assistant_reply_kind(metadata.reply_kind),
    )?;
    let probe = AgentTurnReceiptProbe {
        id: durable_agent_id(&id, &request.turn_id),
        authz: current.principal.authz.clone(),
        deployment_manifest_digest: manifest.digest.clone(),
        environment: state.store.session_agent_environment().to_owned(),
        provider_name: metadata.provider_id.clone(),
        model_name: metadata.model.clone(),
    };
    if let Some(replayed) = state
        .store
        .agent_start_receipt_for_actor(
            &current.principal.authz,
            &id,
            &request,
            &idempotency_key,
            &probe,
        )
        .await?
    {
        kick_agent_model_worker(&state);
        return Ok((StatusCode::ACCEPTED, Json(replayed.start)).into_response());
    }
    let knowledge = state
        .store
        .session_agent_knowledge_context(&current.principal.authz, &request.user_message)
        .await?;
    let checkpoint = state
        .store
        .session_context_checkpoint_for_actor(
            &current.principal.authz,
            &id,
            request.expected_sequence,
        )
        .await?;
    let reply_turns = state
        .store
        .session_reply_turns_after_for_actor(
            &current.principal.authz,
            &id,
            checkpoint
                .as_ref()
                .map_or(0, |checkpoint| checkpoint.source_end_sequence),
            request.expected_sequence,
            AGENT_REQUEST_MAX_HISTORY_PAIRS_WITH_CONTEXT,
        )
        .await?;
    let mut reply_request = ReplyRequest::from_session_history_for_agent_with_optional_system_prompt_checkpoint_and_context(
            &reply_turns,
            request.user_message.clone(),
            Some(prompt.content.as_str()),
            checkpoint
                .as_ref()
                .map(|checkpoint| checkpoint.summary_text.as_str()),
            knowledge.snapshot.snapshot().canonical_context(),
        )
        .map_err(agent_request_builder_error)?;
    reply_request.tools = agent_tools_from_manifest(&manifest);
    let request_json =
        persisted_agent_reply_request(&reply_request).map_err(ApiError::agent_request_too_large)?;
    let agent = AgentTurnSpec {
        id: probe.id,
        authz: probe.authz,
        environment: probe.environment,
        provider_name: probe.provider_name,
        model_name: probe.model_name,
        request_json,
        manifest,
        knowledge,
    };
    let response = state
        .store
        .start_turn_and_enqueue_agent_for_actor(
            &current.principal.authz,
            &id,
            request,
            &idempotency_key,
            agent,
        )
        .await?;
    kick_agent_model_worker(&state);
    Ok((StatusCode::ACCEPTED, Json(response.start)).into_response())
}

#[cfg(test)]
async fn test_start_turn(
    State(state): State<ApiState>,
    Extension(current): Extension<CurrentAuth>,
    Path(id): Path<String>,
    headers: HeaderMap,
    payload: Result<Json<StartTurnRequest>, JsonRejection>,
) -> Result<Json<protocol::StartTurnResponse>, ApiError> {
    state
        .store
        .authorize_session_for_actor(&current.principal.authz, &id)
        .await?;
    let Json(request) = payload.map_err(ApiError::invalid_json)?;
    let idempotency_key = required_idempotency_key(&headers)?;
    Ok(Json(
        state
            .store
            .start_turn_for_actor(&current.principal.authz, &id, request, &idempotency_key)
            .await?,
    ))
}

#[cfg(test)]
async fn test_flush_turn(
    State(state): State<ApiState>,
    Extension(current): Extension<CurrentAuth>,
    Path((id, turn_id)): Path<(String, String)>,
    headers: HeaderMap,
    payload: Result<Json<protocol::FlushSessionRequest>, JsonRejection>,
) -> Result<Json<protocol::FlushSessionResponse>, ApiError> {
    state
        .store
        .authorize_session_for_actor(&current.principal.authz, &id)
        .await?;
    let Json(request) = payload.map_err(ApiError::invalid_json)?;
    let idempotency_key = required_idempotency_key(&headers)?;
    if turn_id != request.turn_id {
        return Err(ApiError::bad_request(
            "turn_id_mismatch",
            "The turn ID in the path must match the request body",
        ));
    }
    Ok(Json(
        state
            .store
            .flush_turn_for_actor(&current.principal.authz, &id, request, &idempotency_key)
            .await?,
    ))
}

async fn run_detail(
    State(state): State<ApiState>,
    Extension(current): Extension<CurrentAuth>,
    Path(id): Path<String>,
    query: Result<Query<RunDetailQuery>, QueryRejection>,
) -> Result<Json<RunDetail>, ApiError> {
    state
        .store
        .authorize_run_for_actor(&current.principal.authz, &id)
        .await?;
    let Query(query) = query.map_err(ApiError::invalid_query)?;
    Ok(Json(
        state
            .store
            .run_detail_for_actor(
                &current.principal.authz,
                &id,
                query.events_before.as_deref(),
                query.events_limit.unwrap_or(EVENT_PAGE_DEFAULT_LIMIT),
            )
            .await?,
    ))
}

async fn review_decision(
    State(state): State<ApiState>,
    Extension(current): Extension<CurrentAuth>,
    Path((id, approval_id)): Path<(String, String)>,
    headers: HeaderMap,
    payload: Result<Json<ReviewRequest>, JsonRejection>,
) -> Result<Json<ReviewResponse>, ApiError> {
    state
        .store
        .authorize_run_for_actor(&current.principal.authz, &id)
        .await?;
    let Json(request) = payload.map_err(ApiError::invalid_json)?;
    let header_key = required_idempotency_key(&headers)?;

    if let Some(body_key) = &request.idempotency_key
        && &header_key != body_key
    {
        return Err(ApiError::bad_request(
            "idempotency_key_mismatch",
            "Idempotency-Key header and request body must match",
        ));
    }

    Ok(Json(
        state
            .store
            .review_for_actor(
                &current.principal.authz,
                &id,
                &approval_id,
                request,
                &header_key,
            )
            .await?,
    ))
}

async fn agent_review_decision(
    State(state): State<ApiState>,
    Extension(current): Extension<CurrentAuth>,
    Path((id, turn_id, call_id)): Path<(String, String, String)>,
    headers: HeaderMap,
    payload: Result<Json<ReviewRequest>, JsonRejection>,
) -> Result<Json<AgentReviewResponse>, ApiError> {
    let Json(request) = payload.map_err(ApiError::invalid_json)?;
    let header_key = required_idempotency_key(&headers)?;
    if let Some(body_key) = &request.idempotency_key
        && body_key != &header_key
    {
        return Err(ApiError::bad_request(
            "idempotency_key_mismatch",
            "Idempotency-Key header and request body must match",
        ));
    }

    let next_request_json = if request.decision == ReviewDecision::Reject {
        let context = state
            .store
            .agent_review_context_for_actor(&current.principal.authz, &id, &turn_id, &call_id)
            .await?;
        let requires_continuation = context.work.call.status
            == AgentToolCallStatus::WaitingApproval
            && state
                .store
                .agent_rejection_requires_continuation(&context, request.note.as_deref())?;
        if requires_continuation {
            let result = protocol::agent_approval_rejected_result(
                &context.work.call.call_id,
                request.note.as_deref(),
            );
            continuation_request_json_for_work(&context.work, &result)
        } else {
            None
        }
    } else {
        None
    };
    let result = state
        .store
        .review_agent_tool_for_actor(
            &current.principal.authz,
            &id,
            &turn_id,
            AgentReviewCommit {
                call_id,
                decision: request.decision,
                note: request.note,
                idempotency_key: header_key,
                next_request_json,
            },
        )
        .await?;
    if result.response.call.status == AgentToolCallStatus::Queued {
        kick_agent_tool_worker(&state);
    }
    if result.queued_model_job.is_some() {
        kick_agent_model_worker(&state);
    }
    Ok(Json(result.response))
}

fn required_idempotency_key(headers: &HeaderMap) -> Result<String, ApiError> {
    let mut values = headers.get_all("idempotency-key").iter();
    let value = values.next().ok_or_else(|| {
        ApiError::bad_request(
            "missing_idempotency_key",
            "Idempotency-Key header is required for this command",
        )
    })?;
    if values.next().is_some() {
        return Err(ApiError::bad_request(
            "invalid_idempotency_key",
            "Exactly one Idempotency-Key header is required",
        ));
    }
    let key = value.to_str().map_err(|_| {
        ApiError::bad_request(
            "invalid_idempotency_key",
            "Idempotency-Key must contain visible ASCII characters only",
        )
    })?;
    protocol::validate_idempotency_key(key).map_err(|error| {
        ApiError::bad_request(
            "invalid_idempotency_key",
            format!("Idempotency-Key {error}"),
        )
    })?;
    Ok(key.to_owned())
}

fn validate_start_turn_envelope(request: &StartTurnRequest) -> Result<(), ApiError> {
    for (field, result) in [
        ("turn ID", protocol::validate_turn_id(&request.turn_id)),
        (
            "user message",
            protocol::validate_user_message(&request.user_message),
        ),
    ] {
        result.map_err(|error| {
            ApiError::bad_request("invalid_session_request", format!("{field} {error}"))
        })?;
    }
    Ok(())
}

fn validate_agent_initial_content_budget(
    system_prompt: &str,
    user_message: &str,
) -> Result<(), ApiError> {
    let user_message_budget = AGENT_REQUEST_INITIAL_CONTENT_MAX_BYTES
        .checked_sub(system_prompt.len())
        .ok_or_else(|| {
            ApiError::internal_contract(
                "the configured Agent system prompt exceeds the initial content budget",
            )
        })?;
    if user_message.len() > user_message_budget {
        return Err(ApiError::agent_request_too_large(
            ProviderError::InvalidRequest("conversation context is too large"),
        ));
    }
    Ok(())
}

fn agent_request_builder_error(error: ProviderError) -> ApiError {
    if matches!(
        &error,
        ProviderError::InvalidRequest(detail) if *detail == "conversation context is too large"
    ) {
        ApiError::agent_request_too_large(error)
    } else {
        ApiError::internal_contract(&error.to_string())
    }
}

async fn session_events(
    State(state): State<ApiState>,
    Extension(current): Extension<CurrentAuth>,
    Path(id): Path<String>,
    headers: HeaderMap,
    query: Result<Query<EventsQuery>, QueryRejection>,
) -> Result<Response, ApiError> {
    state
        .store
        .authorize_session_for_actor(&current.principal.authz, &id)
        .await?;
    let Query(query) = query.map_err(ApiError::invalid_query)?;
    let after = event_cursor(&headers, query)?;
    if !sse_auth_is_current(&state.store, &current).await {
        return Err(ApiError::unauthorized());
    }
    let authz = current.principal.authz.clone();
    let sse_lease = acquire_sse_lease(&state.sse_capacity, &authz)?;
    let mut feed = state
        .store
        .session_event_page_feed_for_actor(&authz, &id, after, protocol::EVENT_PAGE_DEFAULT_LIMIT)
        .await?;
    let store = state.store.clone();
    let durable_ledger_poll_interval = state.durable_ledger_poll_interval;
    let broadcast_hints_enabled = state.broadcast_hints_enabled;
    let session_id = id;

    let stream = async_stream::stream! {
        let _sse_lease = sse_lease;
        let mut cursor = after;
        let mut pending = feed.replay.items.into_iter();
        let mut catch_up = feed.replay.has_more;
        let mut stream_opened = false;

        let mut durable_poll = tokio::time::interval_at(
            Instant::now() + durable_ledger_poll_interval,
            durable_ledger_poll_interval,
        );
        durable_poll.set_missed_tick_behavior(MissedTickBehavior::Delay);

        'stream: loop {
            for event in pending.by_ref() {
                if event.sequence <= cursor {
                    eprintln!("zeus Session SSE page did not advance its durable cursor");
                    break 'stream;
                }
                cursor = event.sequence;
                yield Ok::<Event, Infallible>(session_sse_event(&event));
            }
            if catch_up {
                tokio::task::yield_now().await;
                if !sse_auth_is_current(&store, &current).await {
                    break;
                }
                match store
                    .session_event_page_for_actor(
                        &authz,
                        &session_id,
                        cursor,
                        protocol::EVENT_PAGE_DEFAULT_LIMIT,
                    )
                    .await
                {
                    Ok(page) => {
                        if page.items.is_empty() {
                            eprintln!("zeus Session SSE page reported more data without progress");
                            break;
                        }
                        catch_up = page.has_more;
                        pending = page.items.into_iter();
                        continue;
                    }
                    Err(error) => {
                        eprintln!("zeus SSE durable catch-up failed for a session: {error:?}");
                        break;
                    }
                }
            }

            if !stream_opened {
                yield Ok(Event::default().comment("stream-open"));
                stream_opened = true;
            }

            tokio::select! {
                received = feed.receiver.recv(), if broadcast_hints_enabled => match received {
                    Ok(published) => {
                        if !sse_auth_is_current(&store, &current).await {
                            break;
                        }
                        if published.session_id == session_id && published.event.sequence > cursor {
                            // A post-commit broadcast is only a wake hint: two
                            // commits can publish out of order. Always advance
                            // from the ordered durable ledger so a later hint
                            // cannot make an earlier event permanently vanish.
                            match store
                                .session_event_page_for_actor(
                                    &authz,
                                    &session_id,
                                    cursor,
                                    protocol::EVENT_PAGE_DEFAULT_LIMIT,
                                )
                                .await
                            {
                                Ok(page) => {
                                    catch_up = page.has_more;
                                    pending = page.items.into_iter();
                                }
                                Err(error) => {
                                    eprintln!(
                                        "zeus SSE durable replay failed for a session: {error:?}"
                                    );
                                    break;
                                }
                            }
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(_)) => {
                        if !sse_auth_is_current(&store, &current).await {
                            break;
                        }
                        match store
                            .session_event_page_for_actor(
                                &authz,
                                &session_id,
                                cursor,
                                protocol::EVENT_PAGE_DEFAULT_LIMIT,
                            )
                            .await
                        {
                            Ok(page) => {
                                catch_up = page.has_more;
                                pending = page.items.into_iter();
                            }
                            Err(error) => {
                                eprintln!(
                                    "zeus SSE durable replay failed for a session: {error:?}"
                                );
                                break;
                            }
                        }
                    }
                    Err(broadcast::error::RecvError::Closed) => break,
                },
                _ = durable_poll.tick() => {
                    if !sse_auth_is_current(&store, &current).await {
                        break;
                    }
                    match store
                        .session_event_page_for_actor(
                            &authz,
                            &session_id,
                            cursor,
                            protocol::EVENT_PAGE_DEFAULT_LIMIT,
                        )
                        .await
                    {
                        Ok(page) => {
                            catch_up = page.has_more;
                            pending = page.items.into_iter();
                        }
                        Err(error) => {
                            eprintln!("zeus SSE durable poll failed for a session: {error:?}");
                            break;
                        }
                    }
                }
            }
        }
    };

    Ok(Sse::new(stream)
        .keep_alive(
            KeepAlive::new()
                .interval(Duration::from_secs(15))
                .text("keep-alive"),
        )
        .into_response())
}

async fn run_events(
    State(state): State<ApiState>,
    Extension(current): Extension<CurrentAuth>,
    Path(id): Path<String>,
    headers: HeaderMap,
    query: Result<Query<EventsQuery>, QueryRejection>,
) -> Result<Response, ApiError> {
    state
        .store
        .authorize_run_for_actor(&current.principal.authz, &id)
        .await?;
    let Query(query) = query.map_err(ApiError::invalid_query)?;
    let after = event_cursor(&headers, query)?;
    if !sse_auth_is_current(&state.store, &current).await {
        return Err(ApiError::unauthorized());
    }
    let authz = current.principal.authz.clone();
    let sse_lease = acquire_sse_lease(&state.sse_capacity, &authz)?;
    let mut feed = state
        .store
        .event_page_feed_for_actor(&authz, &id, after, protocol::EVENT_PAGE_DEFAULT_LIMIT)
        .await?;
    let store = state.store.clone();
    let durable_ledger_poll_interval = state.durable_ledger_poll_interval;
    let broadcast_hints_enabled = state.broadcast_hints_enabled;
    let run_id = id;

    let stream = async_stream::stream! {
        let _sse_lease = sse_lease;
        let mut cursor = after;
        let mut pending = feed.replay.items.into_iter();
        let mut catch_up = feed.replay.has_more;
        let mut stream_opened = false;

        // Broadcast is a same-process latency hint only. Poll the durable
        // ledger at a bounded interval so commits without a local hint are
        // still observed. Delay missed ticks to avoid catch-up bursts.
        let mut durable_poll = tokio::time::interval_at(
            Instant::now() + durable_ledger_poll_interval,
            durable_ledger_poll_interval,
        );
        durable_poll.set_missed_tick_behavior(MissedTickBehavior::Delay);

        'stream: loop {
            for event in pending.by_ref() {
                if event.sequence <= cursor {
                    eprintln!("zeus Run SSE page did not advance its durable cursor");
                    break 'stream;
                }
                cursor = event.sequence;
                yield Ok::<Event, Infallible>(sse_event(&event));
            }
            if catch_up {
                tokio::task::yield_now().await;
                if !sse_auth_is_current(&store, &current).await {
                    break;
                }
                match store
                    .run_event_page_for_actor(
                        &authz,
                        &run_id,
                        cursor,
                        protocol::EVENT_PAGE_DEFAULT_LIMIT,
                    )
                    .await
                {
                    Ok(page) => {
                        if page.items.is_empty() {
                            eprintln!("zeus Run SSE page reported more data without progress");
                            break;
                        }
                        catch_up = page.has_more;
                        pending = page.items.into_iter();
                        continue;
                    }
                    Err(error) => {
                        eprintln!("zeus SSE durable catch-up failed for run {run_id}: {error:?}");
                        break;
                    }
                }
            }

            if !stream_opened {
                // Flush a harmless SSE comment when the client is already at
                // the ledger head. Historical events have already flushed the
                // response while a paged replay was in progress.
                yield Ok(Event::default().comment("stream-open"));
                stream_opened = true;
            }

            tokio::select! {
                received = feed.receiver.recv(), if broadcast_hints_enabled => match received {
                    Ok(published) => {
                        if !sse_auth_is_current(&store, &current).await {
                            break;
                        }
                        // Broadcast is only a wake hint. Separate commits can
                        // publish out of order, so advancing directly to the
                        // hinted sequence could permanently skip an earlier
                        // durable event.
                        match run_events_for_hint(
                            &store,
                            &authz,
                            &run_id,
                            cursor,
                            &published,
                        )
                        .await
                        {
                            Ok(Some(page)) => {
                                catch_up = page.has_more;
                                pending = page.items.into_iter();
                            }
                            Ok(None) => {}
                            Err(error) => {
                                eprintln!(
                                    "zeus SSE durable replay failed for run {run_id}: {error:?}"
                                );
                                break;
                            }
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(_)) => {
                        if !sse_auth_is_current(&store, &current).await {
                            break;
                        }
                        // Recover a slow client from the append-only ledger
                        // instead of silently skipping events.
                        match store
                            .run_event_page_for_actor(
                                &authz,
                                &run_id,
                                cursor,
                                protocol::EVENT_PAGE_DEFAULT_LIMIT,
                            )
                            .await
                        {
                            Ok(page) => {
                                catch_up = page.has_more;
                                pending = page.items.into_iter();
                            }
                            Err(error) => {
                                eprintln!(
                                    "zeus SSE durable replay failed for run {run_id}: {error:?}"
                                );
                                break;
                            }
                        }
                    }
                    Err(broadcast::error::RecvError::Closed) => break,
                },
                _ = durable_poll.tick() => {
                    if !sse_auth_is_current(&store, &current).await {
                        break;
                    }
                    match store
                        .run_event_page_for_actor(
                            &authz,
                            &run_id,
                            cursor,
                            protocol::EVENT_PAGE_DEFAULT_LIMIT,
                        )
                        .await
                    {
                        Ok(page) => {
                            catch_up = page.has_more;
                            pending = page.items.into_iter();
                        }
                        Err(error) => {
                            eprintln!(
                                "zeus SSE durable poll failed for run {run_id}: {error:?}"
                            );
                            break;
                        }
                    }
                }
            }
        }
    };

    Ok(Sse::new(stream)
        .keep_alive(
            KeepAlive::new()
                .interval(Duration::from_secs(15))
                .text("keep-alive"),
        )
        .into_response())
}

async fn sse_auth_is_current(store: &DemoStore, current: &CurrentAuth) -> bool {
    matches!(
        store.authenticate(&current.session_token_hash).await,
        Ok(Some(principal))
            if principal.authz == current.principal.authz
    )
}

async fn run_events_for_hint(
    store: &DemoStore,
    context: &AuthzContext,
    run_id: &str,
    cursor: u64,
    published: &PublishedEvent,
) -> Result<Option<protocol::RunEventPage>, StoreError> {
    if published.run_id != run_id || published.event.sequence <= cursor {
        return Ok(None);
    }
    store
        .run_event_page_for_actor(context, run_id, cursor, protocol::EVENT_PAGE_DEFAULT_LIMIT)
        .await
        .map(Some)
}

fn sse_event(event: &protocol::RunEvent) -> Event {
    Event::default()
        .event("run.event")
        .id(event.sequence.to_string())
        .data(serde_json::to_string(event).expect("RunEvent must serialize"))
}

fn session_sse_event(event: &SessionEvent) -> Event {
    Event::default()
        .event("session.event")
        .id(event.sequence.to_string())
        .data(serde_json::to_string(event).expect("SessionEvent must serialize"))
}

fn event_cursor(headers: &HeaderMap, query: EventsQuery) -> Result<u64, ApiError> {
    let mut header_values = headers.get_all("last-event-id").iter();
    let header_cursor = header_values
        .next()
        .map(|value| {
            value
                .to_str()
                .map_err(|_| ())
                .and_then(|value| value.parse::<u64>().map_err(|_| ()))
                .map_err(|_| invalid_event_cursor("Last-Event-ID must be an unsigned integer"))
        })
        .transpose()?;
    if header_values.next().is_some() {
        return Err(invalid_event_cursor(
            "Exactly one Last-Event-ID header is allowed",
        ));
    }
    // EventSource keeps the original query string when reconnecting but sends
    // its newer cursor in Last-Event-ID. Prefer that header so reconnects do
    // not repeatedly replay from the page's initial sequence.
    let cursor = header_cursor.or(query.after).unwrap_or(0);
    if cursor > i64::MAX as u64 {
        return Err(invalid_event_cursor(
            "The event cursor exceeds the supported sequence range",
        ));
    }
    Ok(cursor)
}

fn invalid_event_cursor(detail: &'static str) -> ApiError {
    ApiError::bad_request("invalid_event_cursor", detail)
}

async fn not_found() -> ApiError {
    ApiError::new(
        StatusCode::NOT_FOUND,
        "route_not_found",
        "Route not found",
        "The requested API route does not exist",
    )
}

#[derive(Debug)]
struct ApiError {
    status: StatusCode,
    problem: Box<ProblemDetails>,
    headers: HeaderMap,
}

impl ApiError {
    fn new(
        status: StatusCode,
        code: impl Into<String>,
        title: impl Into<String>,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            status,
            problem: Box::new(ProblemDetails::new(status.as_u16(), code, title, detail)),
            headers: HeaderMap::new(),
        }
    }

    fn bad_request(code: impl Into<String>, detail: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, code, "Invalid request", detail)
    }

    fn invalid_json(rejection: JsonRejection) -> Self {
        match rejection.status() {
            StatusCode::PAYLOAD_TOO_LARGE => Self::new(
                StatusCode::PAYLOAD_TOO_LARGE,
                "request_body_too_large",
                "Request body too large",
                "The JSON request body exceeds the allowed size",
            ),
            StatusCode::UNSUPPORTED_MEDIA_TYPE => Self::new(
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                "unsupported_media_type",
                "Unsupported media type",
                "Content-Type must be application/json",
            ),
            StatusCode::UNPROCESSABLE_ENTITY => Self::new(
                StatusCode::UNPROCESSABLE_ENTITY,
                "invalid_json_data",
                "Invalid JSON data",
                "The JSON body does not match the request schema",
            ),
            _ => Self::bad_request("invalid_json", "The request body must contain valid JSON"),
        }
    }

    fn invalid_query(rejection: QueryRejection) -> Self {
        Self::bad_request("invalid_query", rejection.body_text())
    }

    fn unauthorized() -> Self {
        Self::new(
            StatusCode::UNAUTHORIZED,
            "authentication_required",
            "Authentication required",
            "Sign in to access this Zeus resource",
        )
        .with_no_store()
    }

    fn invalid_login() -> Self {
        Self::new(
            StatusCode::UNAUTHORIZED,
            "invalid_credentials",
            "Sign-in failed",
            "The username or password is invalid",
        )
        .with_no_store()
    }

    fn invalid_bootstrap() -> Self {
        Self::new(
            StatusCode::UNAUTHORIZED,
            "invalid_bootstrap_token",
            "Owner setup failed",
            "The bootstrap token is invalid, expired, or already used",
        )
        .with_no_store()
    }

    fn invalid_member_setup() -> Self {
        Self::new(
            StatusCode::UNAUTHORIZED,
            "invalid_member_setup_token",
            "Member setup failed",
            "The member setup token is invalid, expired, or already used",
        )
        .with_no_store()
    }

    fn member_setup_not_pending() -> Self {
        Self::new(
            StatusCode::CONFLICT,
            "member_setup_not_pending",
            "Member setup is not pending",
            "Setup tokens can only be rotated for an active member that has not completed setup",
        )
        .with_no_store()
    }

    fn permission_denied() -> Self {
        Self::new(
            StatusCode::FORBIDDEN,
            "permission_denied",
            "Permission denied",
            "The current account membership cannot perform this operation",
        )
        .with_no_store()
    }

    fn membership_revision_conflict() -> Self {
        Self::new(
            StatusCode::CONFLICT,
            "membership_revision_conflict",
            "Membership revision conflict",
            "The account membership changed; refresh it and retry",
        )
        .with_no_store()
    }

    fn audit_storage_exhausted() -> Self {
        Self::new(
            StatusCode::INSUFFICIENT_STORAGE,
            "audit_storage_exhausted",
            "Account audit storage exhausted",
            "Export account audit history or release legal hold before retrying",
        )
        .with_no_store()
    }

    fn audit_policy_revision_conflict() -> Self {
        Self::new(
            StatusCode::CONFLICT,
            "audit_policy_revision_conflict",
            "Account audit policy revision conflict",
            "The account audit policy changed; refresh it and retry",
        )
        .with_no_store()
    }

    fn audit_export_too_large(max_bytes: usize) -> Self {
        Self::new(
            StatusCode::INSUFFICIENT_STORAGE,
            "audit_export_too_large",
            "Account audit export is too large",
            format!(
                "The complete audit export exceeds the {max_bytes}-byte response limit; use the paginated events endpoint"
            ),
        )
        .with_no_store()
    }

    fn internal_contract(detail: &str) -> Self {
        eprintln!("zeus API encountered an internal response contract failure: {detail}");
        Self::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "runtime_unavailable",
            "Runtime is unavailable",
            "The runtime could not produce a safe response",
        )
        .with_no_store()
    }

    fn invalid_csrf() -> Self {
        Self::new(
            StatusCode::FORBIDDEN,
            "invalid_csrf_token",
            "Request verification failed",
            "Refresh the page and retry the request",
        )
    }

    fn invalid_origin() -> Self {
        Self::new(
            StatusCode::FORBIDDEN,
            "invalid_origin",
            "Request origin rejected",
            "The request must originate from this Zeus host",
        )
    }

    fn from_ingress_error(error: IngressRequestError) -> Self {
        match error {
            IngressRequestError::UntrustedPeer => Self::new(
                StatusCode::FORBIDDEN,
                "untrusted_ingress_peer",
                "Ingress peer rejected",
                "This Zeus endpoint only accepts traffic from a configured trusted proxy",
            ),
            IngressRequestError::InvalidForwarded => Self::new(
                StatusCode::BAD_REQUEST,
                "invalid_forwarded_request",
                "Forwarded request rejected",
                "The trusted proxy metadata is missing, ambiguous, or inconsistent with the public Zeus origin",
            ),
        }
        .with_no_store()
    }

    fn auth_unavailable(error: &(impl std::fmt::Display + ?Sized)) -> Self {
        eprintln!("zeus authentication subsystem failed: {error}");
        Self::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "authentication_unavailable",
            "Authentication is unavailable",
            "The authentication subsystem could not process the request safely",
        )
        .with_no_store()
    }

    fn reply_unavailable(error: ProviderError) -> Self {
        eprintln!("zeus reply provider configuration failed closed: {error}");
        Self::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "reply_provider_unavailable",
            "Reply provider is unavailable",
            "The reply provider configuration cannot be persisted safely",
        )
        .with_no_store()
    }

    fn agent_request_too_large(error: ProviderError) -> Self {
        eprintln!("zeus rejected an Agent request outside its durable envelope: {error}");
        Self::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            "agent_request_too_large",
            "Agent request is too large",
            "The bounded Agent request cannot fit in durable storage",
        )
        .with_no_store()
    }

    fn rate_limited(code: &'static str, title: &'static str, retry_after: Duration) -> Self {
        Self::new(
            StatusCode::TOO_MANY_REQUESTS,
            code,
            title,
            "Too many authentication attempts were received; retry later",
        )
        .with_retry_after(retry_after)
        .with_no_store()
    }

    fn sse_capacity_exceeded(retry_after: Duration) -> Self {
        Self::new(
            StatusCode::TOO_MANY_REQUESTS,
            "sse_capacity_exceeded",
            "Event stream capacity exceeded",
            "Too many event streams are open; retry later",
        )
        .with_retry_after(retry_after)
        .with_no_store()
    }

    fn storage_quota_exceeded() -> Self {
        Self::new(
            StatusCode::TOO_MANY_REQUESTS,
            "storage_quota_exceeded",
            "Storage capacity exceeded",
            "The durable storage limit for this Zeus instance has been reached",
        )
        .with_no_store()
    }

    fn physical_storage_exhausted() -> Self {
        Self::new(
            StatusCode::INSUFFICIENT_STORAGE,
            "physical_storage_exhausted",
            "Physical storage capacity exhausted",
            "SQLite cannot safely accept new durable work at the current disk watermark",
        )
        .with_no_store()
    }

    fn sqlite_operation_capacity_exceeded() -> Self {
        Self::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "sqlite_operation_capacity_exceeded",
            "SQLite operation capacity exceeded",
            "The durable store is temporarily at its blocking-operation capacity",
        )
        .with_retry_after(Duration::from_secs(1))
        .with_no_store()
    }

    fn reply_queue_capacity_exceeded() -> Self {
        Self::new(
            StatusCode::TOO_MANY_REQUESTS,
            "reply_queue_capacity_exceeded",
            "Reply queue capacity exceeded",
            "Too many assistant replies are active; retry later",
        )
        .with_retry_after(Duration::from_secs(2))
        .with_no_store()
    }

    fn dispatch_queue_capacity_exceeded() -> Self {
        Self::new(
            StatusCode::TOO_MANY_REQUESTS,
            "dispatch_queue_capacity_exceeded",
            "Dispatch queue capacity exceeded",
            "Too many tool dispatches are active; retry later",
        )
        .with_retry_after(Duration::from_secs(2))
        .with_no_store()
    }

    fn auth_session_capacity_exceeded() -> Self {
        Self::new(
            StatusCode::TOO_MANY_REQUESTS,
            "auth_session_capacity_exceeded",
            "Sign-in session capacity exceeded",
            "Too many authentication sessions are active for this Zeus instance",
        )
        .with_no_store()
    }

    fn finalization_unavailable(error: &StoreError) -> Self {
        eprintln!("zeus durable finalization reservation failed closed: {error:?}");
        Self::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "runtime_unavailable",
            "Runtime is unavailable",
            "The runtime cannot safely finalize durable work",
        )
        .with_no_store()
    }

    fn unavailable_message(detail: &'static str) -> Self {
        eprintln!("zeus API capacity state is unavailable");
        Self::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "service_unavailable",
            "Service is unavailable",
            detail,
        )
        .with_no_store()
    }

    fn with_no_store(mut self) -> Self {
        self.headers
            .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        self
    }

    fn with_retry_after(mut self, retry_after: Duration) -> Self {
        let seconds = retry_after.as_secs() + u64::from(retry_after.subsec_nanos() > 0);
        let value = HeaderValue::from_str(&seconds.max(1).to_string())
            .expect("Retry-After seconds must form a valid header value");
        self.headers.insert(header::RETRY_AFTER, value);
        self
    }

    fn internal_runtime_error(error: &StoreError) -> Self {
        eprintln!("zeus request failed an internal runtime invariant: {error:?}");
        Self::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "runtime_unavailable",
            "Runtime is unavailable",
            "The runtime could not process the request safely",
        )
        .with_no_store()
    }

    fn unavailable(error: &StoreError) -> Self {
        eprintln!("zeus request failed because the runtime is unavailable: {error:?}");
        Self::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "runtime_unavailable",
            "Runtime is unavailable",
            "The runtime is temporarily unavailable",
        )
        .with_no_store()
    }
}

impl From<StoreError> for ApiError {
    fn from(error: StoreError) -> Self {
        match &error {
            StoreError::RunNotFound(id) => Self::new(
                StatusCode::NOT_FOUND,
                "run_not_found",
                "Run not found",
                format!("Run `{id}` does not exist"),
            ),
            StoreError::SessionNotFound(id) => Self::new(
                StatusCode::NOT_FOUND,
                "session_not_found",
                "Session not found",
                format!("Session `{id}` does not exist"),
            ),
            StoreError::SessionTurnNotFound(id) => Self::new(
                StatusCode::NOT_FOUND,
                "session_turn_not_found",
                "Session turn not found",
                format!("Session turn `{id}` does not exist"),
            ),
            StoreError::AgentTurnNotFound(_) => Self::new(
                StatusCode::NOT_FOUND,
                "agent_turn_not_found",
                "Agent turn not found",
                "The requested Agent turn does not exist",
            ),
            StoreError::AgentToolCallNotFound(_) => Self::new(
                StatusCode::NOT_FOUND,
                "agent_tool_call_not_found",
                "Agent tool call not found",
                "The requested Agent tool call does not exist",
            ),
            StoreError::SessionAlreadyExists(id) => Self::new(
                StatusCode::CONFLICT,
                "session_already_exists",
                "Session already exists",
                format!("Session `{id}` already exists"),
            ),
            StoreError::AccountAlreadyConfigured => Self::new(
                StatusCode::CONFLICT,
                "account_already_configured",
                "Owner already configured",
                "This Zeus instance already has an owner account",
            ),
            StoreError::InvalidBootstrapToken => Self::invalid_bootstrap(),
            StoreError::UserNotFound(_) | StoreError::UserDisabled(_) => Self::invalid_login(),
            StoreError::AuthSessionNotFound => Self::unauthorized(),
            StoreError::PermissionDenied => Self::permission_denied(),
            StoreError::MemberNotFound(id) => Self::new(
                StatusCode::NOT_FOUND,
                "member_not_found",
                "Member not found",
                format!("Account member `{id}` does not exist"),
            )
            .with_no_store(),
            StoreError::MemberAlreadyExists(_) => Self::new(
                StatusCode::CONFLICT,
                "member_already_exists",
                "Member already exists",
                "An account member already uses that identity or username",
            )
            .with_no_store(),
            StoreError::MembershipRevisionConflict => Self::membership_revision_conflict(),
            StoreError::LastAccountOwner => Self::new(
                StatusCode::CONFLICT,
                "last_account_owner",
                "Last account owner",
                "The account must retain at least one active owner",
            )
            .with_no_store(),
            StoreError::InvalidMemberSetupToken
            | StoreError::MemberSetupExpired
            | StoreError::MemberSetupAlreadyCompleted => Self::invalid_member_setup(),
            StoreError::MemberSetupTokenGenerationUnavailable => Self::auth_unavailable(&error),
            StoreError::AuditStorageExhausted
            | StoreError::AuditLegalHold
            | StoreError::AuditArchiveRequired => Self::audit_storage_exhausted(),
            StoreError::AuditPolicyConflict => Self::audit_policy_revision_conflict(),
            StoreError::AuditCheckpointConflict => Self::new(
                StatusCode::CONFLICT,
                "audit_checkpoint_conflict",
                "Account audit checkpoint conflict",
                "The audit archive state changed or the checkpoint does not match durable history",
            )
            .with_no_store(),
            StoreError::KnowledgeCatalogRevisionConflict => Self::new(
                StatusCode::CONFLICT,
                "knowledge_catalog_revision_conflict",
                "Knowledge catalog revision conflict",
                "The account knowledge catalog changed; refresh it and retry",
            )
            .with_no_store(),
            StoreError::KnowledgeCatalogRevisionNotFound(revision) => Self::new(
                StatusCode::NOT_FOUND,
                "knowledge_catalog_revision_not_found",
                "Knowledge catalog revision not found",
                format!("Knowledge catalog revision {revision} does not exist"),
            )
            .with_no_store(),
            StoreError::InvalidKnowledgeCatalog(reason) => {
                Self::bad_request("invalid_knowledge_catalog", reason.clone()).with_no_store()
            }
            StoreError::AgentPromptRevisionConflict => Self::new(
                StatusCode::CONFLICT,
                "agent_prompt_revision_conflict",
                "Agent prompt revision conflict",
                "The account Agent prompt changed; refresh it and retry",
            )
            .with_no_store(),
            StoreError::AgentPromptRevisionNotFound(revision) => Self::new(
                StatusCode::NOT_FOUND,
                "agent_prompt_revision_not_found",
                "Agent prompt revision not found",
                format!("Agent prompt revision {revision} does not exist"),
            )
            .with_no_store(),
            StoreError::InvalidAgentPrompt(reason) => {
                Self::bad_request("invalid_agent_prompt", reason.clone()).with_no_store()
            }
            StoreError::AccountReplyProviderRevisionConflict => Self::new(
                StatusCode::CONFLICT,
                "reply_provider_revision_conflict",
                "Reply provider revision conflict",
                "The account reply provider changed; refresh it and retry",
            )
            .with_no_store(),
            StoreError::InvalidAccountReplyProvider(reason) => {
                Self::bad_request("invalid_reply_provider", reason.clone()).with_no_store()
            }
            StoreError::StorageQuotaExceeded | StoreError::SubagentAdmissionRejected => {
                Self::storage_quota_exceeded()
            }
            StoreError::PhysicalStorageExhausted => Self::physical_storage_exhausted(),
            StoreError::OperationCapacityExceeded => Self::sqlite_operation_capacity_exceeded(),
            StoreError::ReplyQueueCapacityExceeded => Self::reply_queue_capacity_exceeded(),
            StoreError::DispatchQueueCapacityExceeded => Self::dispatch_queue_capacity_exceeded(),
            StoreError::AuthSessionCapacityExceeded => Self::auth_session_capacity_exceeded(),
            StoreError::AccountCapacityExceeded => Self::new(
                StatusCode::INSUFFICIENT_STORAGE,
                "account_capacity_exceeded",
                "Account capacity exhausted",
                "The bounded local account set is full",
            )
            .with_no_store(),
            StoreError::FinalizationReservationUnavailable => {
                Self::finalization_unavailable(&error)
            }
            StoreError::InvalidAccountData(reason) => {
                Self::bad_request("invalid_account_data", reason.clone())
            }
            StoreError::RunAlreadyAttached { run_id, session_id } => Self::new(
                StatusCode::CONFLICT,
                "run_already_attached",
                "Run already attached",
                format!("Run `{run_id}` already belongs to session `{session_id}`"),
            ),
            StoreError::InvalidSessionRequest(reason) => {
                Self::bad_request("invalid_session_request", reason.clone())
            }
            StoreError::EmptyIdempotencyKey => {
                Self::bad_request("invalid_idempotency_key", "Idempotency-Key cannot be empty")
            }
            StoreError::IdempotencyConflict => Self::new(
                StatusCode::CONFLICT,
                "idempotency_conflict",
                "Idempotency conflict",
                "The Idempotency-Key was already used with different command input",
            ),
            StoreError::InvalidSessionTransition(_) => Self::new(
                StatusCode::CONFLICT,
                "invalid_session_transition",
                "Session command conflicts with current state",
                "The session state does not allow this command",
            ),
            StoreError::InvalidAgentTransition(detail) => {
                eprintln!("zeus rejected an invalid Agent transition: {detail}");
                Self::new(
                    StatusCode::CONFLICT,
                    "invalid_agent_transition",
                    "Agent command conflicts with current state",
                    "The Agent state does not allow this command",
                )
            }
            StoreError::AgentRevisionConflict => Self::new(
                StatusCode::CONFLICT,
                "agent_revision_conflict",
                "Agent revision conflict",
                "The Agent turn changed; refresh it and retry",
            )
            .with_no_store(),
            StoreError::AgentTodoRevisionConflict { expected, current } => Self::new(
                StatusCode::CONFLICT,
                "agent_todo_revision_conflict",
                "Agent todo revision conflict",
                format!("The todo list changed from expected revision {expected} to {current}"),
            )
            .with_no_store(),
            StoreError::AgentGoalRevisionConflict { expected, current } => Self::new(
                StatusCode::CONFLICT,
                "agent_goal_revision_conflict",
                "Agent goal revision conflict",
                format!("The Goal changed from expected revision {expected} to {current}"),
            )
            .with_no_store(),
            StoreError::AgentOperationInFlight => Self::new(
                StatusCode::CONFLICT,
                "agent_operation_in_flight",
                "Agent tool is already in flight",
                "The Agent turn cannot be cancelled after tool execution has started",
            )
            .with_no_store(),
            StoreError::AgentAlreadyTerminal => Self::new(
                StatusCode::CONFLICT,
                "agent_already_terminal",
                "Agent turn is already terminal",
                "The Agent turn already completed without this cancellation",
            )
            .with_no_store(),
            StoreError::ApprovalNotPending {
                run_id,
                approval_id,
            } => Self::new(
                StatusCode::CONFLICT,
                "approval_not_pending",
                "Approval is not pending",
                format!("Approval {approval_id} is not pending for run {run_id}"),
            ),
            StoreError::PolicyDenied(reason) => Self::new(
                StatusCode::FORBIDDEN,
                "policy_denied",
                "Policy denied the call",
                reason.clone(),
            ),
            StoreError::PolicyChanged(reason) => Self::new(
                StatusCode::CONFLICT,
                "policy_changed",
                "Approval is stale",
                reason.clone(),
            ),
            StoreError::ToolCallNotFound
            | StoreError::AgentModelJobNotFound(_)
            | StoreError::ExecutionInvariant(_)
            | StoreError::Kernel(_)
            | StoreError::SequenceOverflow => Self::internal_runtime_error(&error),
            StoreError::ConcurrentModification => Self::new(
                StatusCode::CONFLICT,
                "concurrent_modification",
                "Concurrent modification",
                "The resource changed while the command was being committed; retry the request",
            ),
            StoreError::EventCursorOutOfRange { .. } => {
                invalid_event_cursor("The event cursor exceeds the supported sequence range")
            }
            StoreError::EventCursorBeyondHead { .. } => Self::new(
                StatusCode::CONFLICT,
                "event_cursor_beyond_head",
                "Event cursor is ahead of the ledger",
                "The event cursor is ahead of the current durable ledger head",
            ),
            StoreError::InvalidPageLimit { .. } => Self::bad_request(
                "invalid_page_limit",
                "The page limit is outside the supported range",
            ),
            StoreError::InvalidPageCursor | StoreError::PageCursorBeyondHead { .. } => {
                Self::bad_request(
                    "invalid_page_cursor",
                    "The page cursor is malformed or belongs to another collection",
                )
            }
            StoreError::PolicyBuild(_)
            | StoreError::ConnectorConfig(_)
            | StoreError::Registry(_)
            | StoreError::Storage(_) => Self::unavailable(&error),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let Self {
            status,
            problem,
            headers,
        } = self;
        let mut response = (
            status,
            [(header::CONTENT_TYPE, "application/problem+json")],
            Json(*problem),
        )
            .into_response();
        response.headers_mut().extend(headers);
        response
    }
}

#[cfg(test)]
mod tests {
    use std::{
        path::{Path, PathBuf},
        sync::{
            Barrier,
            atomic::{AtomicUsize, Ordering},
        },
    };

    use axum::{
        body::Body,
        extract::connect_info::MockConnectInfo,
        http::{Request, header},
    };
    use http_body_util::BodyExt;
    use llm::{ProviderMetadata, ReplyFuture, ReplyResponse};
    use protocol::{
        CreateSessionResponse, DEMO_RUN_ID, FlushSessionResponse, OverviewResponse, ReviewDecision,
        ReviewRequest, ReviewResponse, SessionDetail, SessionForkSummary, SessionStatus,
        SessionSummary, StartTurnResponse,
    };
    use rusqlite::{Connection, params};
    use tenancy::BootstrapToken;
    use terminal::{
        BackendSpawnRequest, TerminalBackend, TerminalBackendSession, TerminalDeadlines,
        TerminalFuture, TerminalReadRequest, TerminalReadResult, TerminalSendRequest,
        TerminalSendResult, TerminalService, TerminalSignal, TerminalStatus, TerminalWaitReason,
    };
    use tower::ServiceExt;

    use super::*;

    #[test]
    fn reply_worker_wake_state_coalesces_kicks_without_losing_a_pending_cycle() {
        let wake = WorkerWakeState::default();
        assert!(wake.request());
        assert!(!wake.request());
        assert!(!wake.request());
        assert!(wake.complete_cycle());
        assert!(!wake.complete_cycle());
        assert!(wake.request());
        assert!(!wake.complete_cycle());
    }

    fn trusted_ingress_policy() -> IngressPolicy {
        IngressPolicy::trusted_proxy_csv("https://zeus.example.com", "127.0.0.0/8,2001:db8::/32")
            .unwrap()
    }

    #[test]
    fn trusted_ingress_configuration_is_canonical_bounded_and_secure() {
        let policy = trusted_ingress_policy();
        assert!(policy.cookie_secure());
        assert_eq!(policy.mode_name(), "trusted-proxy");
        assert_eq!(policy.public_origin(), Some("https://zeus.example.com"));

        for origin in [
            "http://zeus.example.com",
            "https://ZEUS.example.com",
            "https://zeus.example.com/",
            "https://zeus.example.com:443",
            "https://zeus.example.com:0",
            "https://zeus.example.com:0443",
            "https://zeus.example.com:99999",
            "https://zeus.example.com/path",
            "https://zeus.example.com?query=1",
            "https://user@zeus.example.com",
            "https://:8443",
        ] {
            assert!(IngressPolicy::trusted_proxy_csv(origin, "127.0.0.1/32").is_err());
        }
        assert!(
            IngressPolicy::trusted_proxy_csv("https://zeus.example.com:8443", "127.0.0.1/32")
                .is_ok()
        );
        for cidrs in [
            "",
            "127.0.0.1",
            "127.0.0.1/24",
            "127.0.0.1/33",
            "127.0.0.1/32, 2001:db8::/32",
            "127.0.0.1/32,127.0.0.1/32",
        ] {
            assert!(IngressPolicy::trusted_proxy_csv("https://zeus.example.com", cidrs).is_err());
        }
        let too_many_networks = (0..=TRUSTED_PROXY_NETWORK_LIMIT)
            .map(|index| format!("192.0.2.{index}/32"))
            .collect::<Vec<_>>();
        assert!(
            IngressPolicy::trusted_proxy("https://zeus.example.com", &too_many_networks).is_err()
        );
        assert!(
            IngressPolicy::trusted_proxy(
                format!(
                    "https://{}.example.com",
                    "a".repeat(PUBLIC_ORIGIN_MAX_BYTES)
                ),
                ["127.0.0.1/32"],
            )
            .is_err()
        );
    }

    #[test]
    fn trusted_ingress_uses_one_strict_forwarded_hop_and_direct_mode_ignores_spoofing() {
        let policy = trusted_ingress_policy();
        let peer = "127.0.0.42".parse().unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(
            "forwarded",
            HeaderValue::from_static("for=198.51.100.17;proto=https;host=zeus.example.com"),
        );
        assert_eq!(
            effective_client_ip(&policy, peer, &headers).unwrap(),
            "198.51.100.17".parse::<IpAddr>().unwrap()
        );

        headers.insert(
            "forwarded",
            HeaderValue::from_static(
                "for=\"[2001:db8:ffff::17]\";proto=https;host=zeus.example.com",
            ),
        );
        assert_eq!(
            effective_client_ip(&policy, peer, &headers).unwrap(),
            "2001:db8:ffff::17".parse::<IpAddr>().unwrap()
        );
        for forwarded in [
            "for=198.51.100.1;proto=http;host=zeus.example.com",
            "for=198.51.100.1;proto=https;host=internal.example",
            "for=198.51.100.1,for=198.51.100.2;proto=https;host=zeus.example.com",
            "for=198.51.100.1; proto=https;host=zeus.example.com",
            "for=198.51.100.1;proto=https;host=zeus.example.com;by=127.0.0.1",
            "for=2001:db8::17;proto=https;host=zeus.example.com",
            "for=\"198.51.100.1\";proto=https;host=zeus.example.com",
            "for=0.0.0.0;proto=https;host=zeus.example.com",
        ] {
            headers.insert("forwarded", HeaderValue::from_str(forwarded).unwrap());
            assert_eq!(
                effective_client_ip(&policy, peer, &headers),
                Err(IngressRequestError::InvalidForwarded)
            );
        }
        headers.insert(
            "forwarded",
            HeaderValue::from_static("for=198.51.100.18;proto=https;host=zeus.example.com"),
        );
        assert_eq!(
            effective_client_ip(&policy, "2001:db8::42".parse().unwrap(), &headers).unwrap(),
            "198.51.100.18".parse::<IpAddr>().unwrap()
        );
        headers.append(
            "forwarded",
            HeaderValue::from_static("for=198.51.100.19;proto=https;host=zeus.example.com"),
        );
        assert_eq!(
            effective_client_ip(&policy, peer, &headers),
            Err(IngressRequestError::InvalidForwarded)
        );
        assert_eq!(
            effective_client_ip(&policy, "192.0.2.10".parse().unwrap(), &headers),
            Err(IngressRequestError::UntrustedPeer)
        );
        assert_eq!(
            effective_client_ip(&IngressPolicy::direct(false), peer, &headers,).unwrap(),
            peer
        );
    }

    #[test]
    fn trusted_ingress_origin_and_cookie_contract_are_exact() {
        let policy = trusted_ingress_policy();
        let mut headers = HeaderMap::new();
        headers.insert(
            header::ORIGIN,
            HeaderValue::from_static("https://zeus.example.com"),
        );
        headers.insert(header::HOST, HeaderValue::from_static("127.0.0.1:8081"));
        enforce_same_origin(&headers, &policy).unwrap();
        headers.insert(
            header::ORIGIN,
            HeaderValue::from_static("https://other.example.com"),
        );
        assert!(enforce_same_origin(&headers, &policy).is_err());

        let mut cookies = HeaderMap::new();
        set_auth_cookies(&mut cookies, "session", "csrf", policy.cookie_secure()).unwrap();
        let values = cookies
            .get_all(header::SET_COOKIE)
            .iter()
            .map(|value| value.to_str().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(values.len(), 2);
        assert!(values.iter().all(|value| value.contains("; Secure")));
        assert!(values.iter().all(|value| value.contains("SameSite=Strict")));
    }

    #[tokio::test]
    async fn trusted_ingress_rejects_direct_and_ambiguous_requests_before_routing() {
        let base = authenticated_app_with_provider_and_ingress(
            DemoStore::seeded().await.unwrap(),
            trusted_ingress_policy(),
            Arc::new(LocalFallbackProvider::new()),
        )
        .unwrap();
        let trusted = base.clone();
        let missing = trusted
            .clone()
            .oneshot(Request::get("/health/live").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_problem(
            missing,
            StatusCode::BAD_REQUEST,
            "invalid_forwarded_request",
        )
        .await;
        let valid = trusted
            .oneshot(
                Request::get("/health/live")
                    .header(
                        "forwarded",
                        "for=198.51.100.77;proto=https;host=zeus.example.com",
                    )
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(valid.status(), StatusCode::OK);

        let untrusted = base;
        let rejected = untrusted
            .oneshot(
                Request::get("/health/live")
                    .header("x-zeus-test-peer", "192.0.2.10:41000")
                    .header(
                        "forwarded",
                        "for=198.51.100.77;proto=https;host=zeus.example.com",
                    )
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_problem(rejected, StatusCode::FORBIDDEN, "untrusted_ingress_peer").await;
    }

    #[test]
    fn known_result_continuation_is_unavailable_at_the_aggregate_envelope() {
        let tool =
            ReplyToolDefinition::new("dev_marker_write", serde_json::json!({ "type": "object" }));
        let request = ReplyRequest::with_tools(
            [
                ReplyMessage::new(ReplyRole::User, "u".repeat(49_120)),
                ReplyMessage::new(ReplyRole::Assistant, "a".repeat(49_120)),
                ReplyMessage::new(ReplyRole::User, "u".repeat(49_120)),
                ReplyMessage::new(ReplyRole::Assistant, "a".repeat(49_120)),
                ReplyMessage::new(
                    ReplyRole::User,
                    "u".repeat(protocol::USER_MESSAGE_MAX_BYTES),
                ),
            ],
            [tool],
        );
        validate_reply_request(&request).unwrap();
        let call = ReplyToolCall::new(
            "provider-call-envelope",
            "dev_marker_write",
            serde_json::json!({ "marker": "agent-api-approved" }),
        );
        let result = serde_json::json!({ "payload": "x".repeat(256) });

        assert!(continuation_request_json(&request, &call, &result).is_none());
    }

    #[tokio::test]
    async fn exact_agent_completion_retries_without_reinvoking_external_work() {
        let attempts = Arc::new(AtomicUsize::new(0));
        let external_calls = Arc::new(AtomicUsize::new(1));
        let result = retry_agent_durable_progress("test", || {
            let attempts = Arc::clone(&attempts);
            async move {
                if attempts.fetch_add(1, Ordering::Relaxed) < 2 {
                    Err(StoreError::ConcurrentModification)
                } else {
                    Ok("committed")
                }
            }
        })
        .await
        .unwrap();

        assert_eq!(result, "committed");
        assert_eq!(attempts.load(Ordering::Relaxed), 3);
        assert_eq!(external_calls.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn recoverable_agent_drain_keeps_the_worker_running_until_claim_recovers() {
        let wake = WorkerWakeState::default();
        assert!(wake.request());
        let attempts = Arc::new(AtomicUsize::new(0));
        retry_agent_durable_progress("test drain", || {
            let attempts = Arc::clone(&attempts);
            async move {
                if attempts.fetch_add(1, Ordering::Relaxed) < 2 {
                    Err(StoreError::PhysicalStorageExhausted)
                } else {
                    Ok(())
                }
            }
        })
        .await
        .unwrap();

        assert_eq!(attempts.load(Ordering::Relaxed), 3);
        assert_eq!(wake.state.load(Ordering::Acquire), WORKER_RUNNING);
        assert!(!wake.complete_cycle());
    }

    #[tokio::test]
    async fn prepared_start_retry_keeps_the_exact_claim_until_start_is_known() {
        let attempts = Arc::new(AtomicUsize::new(0));
        let expires_at = (chrono::Utc::now() + chrono::Duration::minutes(1))
            .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        let result = retry_prepared_agent_start("test", &expires_at, || {
            let attempts = Arc::clone(&attempts);
            async move {
                if attempts.fetch_add(1, Ordering::Relaxed) < 2 {
                    Err(StoreError::ConcurrentModification)
                } else {
                    Ok("started")
                }
            }
        })
        .await
        .unwrap();

        assert_eq!(result, Some("started"));
        assert_eq!(attempts.load(Ordering::Relaxed), 3);
    }

    #[tokio::test]
    async fn expired_prepared_start_returns_to_safe_reprepare() {
        let attempts = Arc::new(AtomicUsize::new(0));
        let expires_at = (chrono::Utc::now() - chrono::Duration::seconds(1))
            .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        let result: Option<()> = retry_prepared_agent_start("test", &expires_at, || {
            let attempts = Arc::clone(&attempts);
            async move {
                attempts.fetch_add(1, Ordering::Relaxed);
                Err(StoreError::ConcurrentModification)
            }
        })
        .await
        .unwrap();

        assert_eq!(result, None);
        assert_eq!(attempts.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn permanent_agent_completion_error_is_not_retried() {
        let attempts = Arc::new(AtomicUsize::new(0));
        let result: Result<(), StoreError> = retry_agent_durable_progress("test", || {
            let attempts = Arc::clone(&attempts);
            async move {
                attempts.fetch_add(1, Ordering::Relaxed);
                Err(StoreError::InvalidAgentTransition(
                    "permanent test transition".into(),
                ))
            }
        })
        .await;

        assert!(matches!(result, Err(StoreError::InvalidAgentTransition(_))));
        assert_eq!(attempts.load(Ordering::Relaxed), 1);
    }

    struct ManualRateLimitClock {
        now: StdMutex<StdInstant>,
    }

    impl ManualRateLimitClock {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                now: StdMutex::new(StdInstant::now()),
            })
        }

        fn advance(&self, duration: Duration) {
            let mut now = self.now.lock().unwrap();
            *now += duration;
        }
    }

    impl RateLimitClock for ManualRateLimitClock {
        fn now(&self) -> StdInstant {
            *self.now.lock().unwrap()
        }
    }

    fn test_rate_policy(
        global_limit: usize,
        source_limit: usize,
        account_limit: Option<usize>,
    ) -> RateLimitPolicy {
        RateLimitPolicy {
            global_limit,
            source_limit,
            account_limit,
            window: AUTH_RATE_WINDOW,
            key_capacity: 32,
            entry_ttl: AUTH_RATE_ENTRY_TTL,
        }
    }

    #[test]
    fn audit_ndjson_builder_enforces_the_complete_response_byte_bound() {
        let value = serde_json::json!({ "kind": "test" });
        let exact = serde_json::to_vec(&value).unwrap().len() + 1;
        let mut body = Vec::new();
        append_account_audit_ndjson_line(&mut body, &value, exact).unwrap();
        assert_eq!(body.len(), exact);
        assert_eq!(body.last(), Some(&b'\n'));

        let before = body.clone();
        let error = append_account_audit_ndjson_line(&mut body, &value, exact).unwrap_err();
        assert_eq!(error.status, StatusCode::INSUFFICIENT_STORAGE);
        assert_eq!(error.problem.code, "audit_export_too_large");
        assert_eq!(body, before, "a rejected line must not partially append");
    }

    #[test]
    fn auth_rate_limiter_is_windowed_and_memory_bounded() {
        let clock = ManualRateLimitClock::new();
        let limiter = AttemptRateLimiter::new(test_rate_policy(10, 2, Some(10)), clock.clone());
        let source = "192.0.2.10".parse().unwrap();
        assert!(limiter.charge(source, Some("first")).is_ok());
        assert!(limiter.charge(source, Some("second")).is_ok());
        assert!(matches!(
            limiter.charge(source, Some("third")),
            Err(RateLimitError::Limited(retry_after)) if retry_after == AUTH_RATE_WINDOW
        ));

        clock.advance(AUTH_RATE_WINDOW);
        assert!(limiter.charge(source, Some("third")).is_ok());

        let account_limiter =
            AttemptRateLimiter::new(test_rate_policy(10, 10, Some(2)), clock.clone());
        assert!(
            account_limiter
                .charge("192.0.2.21".parse().unwrap(), Some("owner"))
                .is_ok()
        );
        assert!(
            account_limiter
                .charge("192.0.2.22".parse().unwrap(), Some("owner"))
                .is_ok()
        );
        assert!(matches!(
            account_limiter.charge("192.0.2.23".parse().unwrap(), Some("owner")),
            Err(RateLimitError::Limited(_))
        ));

        let global_limiter =
            AttemptRateLimiter::new(test_rate_policy(2, 10, Some(10)), clock.clone());
        assert!(
            global_limiter
                .charge("192.0.2.31".parse().unwrap(), Some("first"))
                .is_ok()
        );
        assert!(
            global_limiter
                .charge("192.0.2.32".parse().unwrap(), Some("second"))
                .is_ok()
        );
        assert!(matches!(
            global_limiter.charge("192.0.2.33".parse().unwrap(), Some("third")),
            Err(RateLimitError::Limited(_))
        ));

        let mut bounded_policy = test_rate_policy(100, 1, None);
        bounded_policy.key_capacity = 2;
        let bounded = AttemptRateLimiter::new(bounded_policy, clock.clone());
        assert!(bounded.charge("192.0.2.11".parse().unwrap(), None).is_ok());
        assert!(bounded.charge("192.0.2.12".parse().unwrap(), None).is_ok());
        assert!(matches!(
            bounded.charge("192.0.2.13".parse().unwrap(), None),
            Err(RateLimitError::Limited(retry_after))
                if retry_after == AUTH_RATE_SWEEP_INTERVAL
        ));
        assert!(matches!(
            bounded.charge("192.0.2.11".parse().unwrap(), None),
            Err(RateLimitError::Limited(_))
        ));
        clock.advance(AUTH_RATE_ENTRY_TTL);
        assert!(bounded.charge("192.0.2.13".parse().unwrap(), None).is_ok());
    }

    #[test]
    fn auth_rate_limiter_check_and_charge_are_atomic_under_concurrency() {
        const ATTEMPTS: usize = 20;
        const ACCEPTED: usize = 5;
        let clock = ManualRateLimitClock::new();
        let limiter = Arc::new(AttemptRateLimiter::new(
            test_rate_policy(ACCEPTED, ATTEMPTS, None),
            clock,
        ));
        let barrier = Arc::new(Barrier::new(ATTEMPTS));
        let accepted = AtomicUsize::new(0);

        std::thread::scope(|scope| {
            for index in 0..ATTEMPTS {
                let limiter = Arc::clone(&limiter);
                let barrier = Arc::clone(&barrier);
                let accepted = &accepted;
                scope.spawn(move || {
                    let source = IpAddr::from([192, 0, 2, (index + 1) as u8]);
                    barrier.wait();
                    if limiter.charge(source, None).is_ok() {
                        accepted.fetch_add(1, Ordering::Relaxed);
                    }
                });
            }
        });

        assert_eq!(accepted.load(Ordering::Relaxed), ACCEPTED);
        let state = limiter.state.lock().unwrap();
        assert_eq!(state.global.unwrap().count, ACCEPTED);
        assert_eq!(state.sources.len(), ACCEPTED);
        assert!(state.sources.len() + state.accounts.len() <= limiter.policy.key_capacity);
    }

    #[test]
    fn sse_capacity_enforces_global_and_actor_limits_until_lease_drop() {
        let capacity = SseCapacity::new(3, 1);
        let alice = test_authz_context("acc-local", "alice", "session-alice");
        let alice_other_account =
            test_authz_context("acc-other", "alice", "session-alice-other-account");
        let bob = test_authz_context("acc-local", "bob", "session-bob");
        let alice_one = capacity.try_acquire(&alice).unwrap();
        assert!(matches!(
            capacity.try_acquire(&alice),
            Err(RateLimitError::Limited(retry_after)) if retry_after == SSE_CAPACITY_RETRY_AFTER
        ));
        let alice_other_account_lease = capacity.try_acquire(&alice_other_account).unwrap();
        let bob_lease = capacity.try_acquire(&bob).unwrap();
        assert!(matches!(
            capacity.try_acquire(&test_authz_context("acc-local", "carol", "session-carol")),
            Err(RateLimitError::Limited(retry_after)) if retry_after == SSE_CAPACITY_RETRY_AFTER
        ));
        drop(alice_one);
        assert!(capacity.try_acquire(&alice).is_ok());
        drop(alice_other_account_lease);
        drop(bob_lease);
    }

    fn test_authz_context(account_id: &str, user_id: &str, auth_session_id: &str) -> AuthzContext {
        AuthzContext {
            account_id: AccountId::from_persistence(account_id).unwrap(),
            user_id: user_id.into(),
            membership_role: MembershipRole::Owner,
            membership_revision: tenancy::MembershipRevision::new(1).unwrap(),
            auth_session_id: AuthSessionId::from_persistence(auth_session_id).unwrap(),
        }
    }

    #[tokio::test]
    async fn json_body_limits_and_rejections_keep_distinct_problem_statuses() {
        let app = test_app().await;

        let unsupported = app
            .clone()
            .oneshot(
                Request::post("/api/v1/sessions")
                    .header("idempotency-key", "unsupported-json")
                    .body(Body::from(r#"{"id":"s","title":"t"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_problem(
            unsupported,
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "unsupported_media_type",
        )
        .await;

        let malformed = app
            .clone()
            .oneshot(
                Request::post("/api/v1/sessions")
                    .header(header::CONTENT_TYPE, "application/json")
                    .header("idempotency-key", "malformed-json")
                    .body(Body::from("{"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_problem(malformed, StatusCode::BAD_REQUEST, "invalid_json").await;

        let invalid_data = app
            .clone()
            .oneshot(
                Request::post("/api/v1/sessions")
                    .header(header::CONTENT_TYPE, "application/json")
                    .header("idempotency-key", "invalid-json-data")
                    .body(Body::from(r#"{"id":1,"title":"t"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_problem(
            invalid_data,
            StatusCode::UNPROCESSABLE_ENTITY,
            "invalid_json_data",
        )
        .await;

        let oversized_command = app
            .clone()
            .oneshot(
                Request::post("/api/v1/sessions")
                    .header(header::CONTENT_TYPE, "application/json")
                    .header("idempotency-key", "oversized-command")
                    .body(Body::from("x".repeat(COMMAND_JSON_BODY_MAX_BYTES + 1)))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_problem(
            oversized_command,
            StatusCode::PAYLOAD_TOO_LARGE,
            "request_body_too_large",
        )
        .await;

        let oversized_without_key = app
            .clone()
            .oneshot(
                Request::post("/api/v1/sessions")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from("x".repeat(COMMAND_JSON_BODY_MAX_BYTES + 1)))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_problem(
            oversized_without_key,
            StatusCode::PAYLOAD_TOO_LARGE,
            "request_body_too_large",
        )
        .await;

        let invalid_data_without_key = app
            .clone()
            .oneshot(
                Request::post("/api/v1/sessions")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(r#"{"id":"s","title":"t","unknown":true}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_problem(
            invalid_data_without_key,
            StatusCode::UNPROCESSABLE_ENTITY,
            "invalid_json_data",
        )
        .await;

        create_test_session(&app, "session-command-envelope").await;
        let medium_message = "m".repeat(AUTH_JSON_BODY_MAX_BYTES * 2);
        let medium_command = app
            .clone()
            .oneshot(
                Request::post("/api/v1/sessions/session-command-envelope/turns")
                    .header(header::CONTENT_TYPE, "application/json")
                    .header("idempotency-key", "medium-command")
                    .body(Body::from(
                        serde_json::json!({
                            "turn_id": "turn-medium-command",
                            "user_message": medium_message,
                            "expected_sequence": 1,
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(medium_command.status(), StatusCode::OK);

        let auth_app = authenticated_app(DemoStore::seeded().await.unwrap(), false)
            .unwrap()
            .layer(MockConnectInfo(test_peer()));
        let oversized_auth = auth_app
            .oneshot(
                Request::post("/api/v1/auth/bootstrap")
                    .header(header::HOST, "zeus.test")
                    .header(header::ORIGIN, "http://zeus.test")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from("x".repeat(AUTH_JSON_BODY_MAX_BYTES + 1)))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_problem(
            oversized_auth,
            StatusCode::PAYLOAD_TOO_LARGE,
            "request_body_too_large",
        )
        .await;
    }

    #[tokio::test]
    async fn forwarded_headers_cannot_evade_the_direct_peer_login_limit() {
        let login_policy = test_rate_policy(10, 2, Some(10));
        let fixture = configured_auth_test_app("xff-rate", login_policy).await;

        for (index, expected) in [
            StatusCode::UNAUTHORIZED,
            StatusCode::UNAUTHORIZED,
            StatusCode::TOO_MANY_REQUESTS,
        ]
        .into_iter()
        .enumerate()
        {
            let mut request = login_request(&format!("missing-{index}"), "Wrong-password-2026");
            request.headers_mut().insert(
                "x-forwarded-for",
                HeaderValue::from_str(&format!("198.51.100.{}", index + 1)).unwrap(),
            );
            request.headers_mut().insert(
                "forwarded",
                HeaderValue::from_str(&format!("for=203.0.113.{}", index + 1)).unwrap(),
            );
            let response = fixture.app.clone().oneshot(request).await.unwrap();
            assert_eq!(response.status(), expected);
            if expected == StatusCode::TOO_MANY_REQUESTS {
                assert_eq!(response.headers()[header::RETRY_AFTER], "60");
                assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
                let problem: ProblemDetails = response_json(response).await;
                assert_eq!(problem.code, "login_rate_limited");
            }
        }

        fixture.cleanup();
    }

    #[tokio::test]
    async fn trusted_proxy_client_ip_drives_the_login_source_limit() {
        let login_policy = test_rate_policy(10, 1, Some(10));
        let ingress =
            IngressPolicy::trusted_proxy("https://zeus.example.com", ["127.0.0.0/8", "::1/128"])
                .unwrap();
        let fixture =
            configured_auth_test_app_with_ingress("trusted-proxy-rate", login_policy, ingress)
                .await;

        for (username, client_ip, expected) in [
            ("missing-first", "198.51.100.10", StatusCode::UNAUTHORIZED),
            (
                "missing-second",
                "198.51.100.10",
                StatusCode::TOO_MANY_REQUESTS,
            ),
            ("missing-third", "198.51.100.11", StatusCode::UNAUTHORIZED),
        ] {
            let mut request = login_request(username, "Wrong-password-2026");
            request.headers_mut().insert(
                header::ORIGIN,
                HeaderValue::from_static("https://zeus.example.com"),
            );
            request.headers_mut().insert(
                header::FORWARDED,
                HeaderValue::from_str(&format!(
                    "for={client_ip};proto=https;host=zeus.example.com"
                ))
                .unwrap(),
            );
            let response = fixture.app.clone().oneshot(request).await.unwrap();
            assert_eq!(response.status(), expected);
            if expected == StatusCode::TOO_MANY_REQUESTS {
                let problem: ProblemDetails = response_json(response).await;
                assert_eq!(problem.code, "login_rate_limited");
            }
        }

        fixture.cleanup();
    }

    #[tokio::test]
    async fn login_limit_is_charged_before_argon_worker_acquisition() {
        let login_policy = test_rate_policy(10, 1, Some(10));
        let fixture = configured_auth_test_app("argon-order", login_policy).await;
        let held_workers = fixture
            .auth
            .password_workers
            .clone()
            .acquire_many_owned(PASSWORD_WORKER_LIMIT as u32)
            .await
            .unwrap();

        let unavailable = fixture
            .app
            .clone()
            .oneshot(login_request("missing-first", "Wrong-password-2026"))
            .await
            .unwrap();
        assert_eq!(unavailable.status(), StatusCode::SERVICE_UNAVAILABLE);

        let limited = fixture
            .app
            .clone()
            .oneshot(login_request("missing-second", "Wrong-password-2026"))
            .await
            .unwrap();
        assert_problem(limited, StatusCode::TOO_MANY_REQUESTS, "login_rate_limited").await;

        drop(held_workers);
        fixture.cleanup();
    }

    #[tokio::test]
    async fn bootstrap_limit_is_charged_before_argon_worker_acquisition() {
        let store = DemoStore::seeded().await.unwrap();
        let clock = ManualRateLimitClock::new();
        let rate_clock: Arc<dyn RateLimitClock> = clock;
        let auth = Arc::new(AuthConfig {
            authenticator: Arc::new(PasswordAuthenticator::new().unwrap()),
            password_workers: Arc::new(Semaphore::new(0)),
            rate_limits: AuthRateLimits::with_policies(
                rate_clock,
                LOGIN_RATE_POLICY,
                test_rate_policy(10, 1, None),
            ),
            ingress: IngressPolicy::direct(false),
        });
        let state = ApiState {
            store,
            durable_ledger_poll_interval: DURABLE_LEDGER_POLL_INTERVAL,
            broadcast_hints_enabled: true,
            auth: Some(auth),
            reply: Some(Arc::new(ReplyExecutor::new(Arc::new(
                LocalFallbackProvider::new(),
            )))),
            sse_capacity: SseCapacity::production(),
        };
        let app = build_authenticated_app(state).layer(MockConnectInfo(test_peer()));
        let presented = BootstrapToken::generate().unwrap();

        let unavailable = app
            .clone()
            .oneshot(bootstrap_request(presented.expose_secret()))
            .await
            .unwrap();
        assert_eq!(unavailable.status(), StatusCode::SERVICE_UNAVAILABLE);

        let limited = app
            .oneshot(bootstrap_request(presented.expose_secret()))
            .await
            .unwrap();
        assert_eq!(limited.headers()[header::RETRY_AFTER], "60");
        assert_eq!(limited.headers()[header::CACHE_CONTROL], "no-store");
        assert_problem(
            limited,
            StatusCode::TOO_MANY_REQUESTS,
            "bootstrap_rate_limited",
        )
        .await;
    }

    #[tokio::test]
    async fn public_member_setup_is_rate_limited_before_token_or_password_work() {
        let store = DemoStore::seeded().await.unwrap();
        let clock = ManualRateLimitClock::new();
        let rate_clock: Arc<dyn RateLimitClock> = clock;
        let auth = Arc::new(AuthConfig {
            authenticator: Arc::new(PasswordAuthenticator::new().unwrap()),
            password_workers: Arc::new(Semaphore::new(0)),
            rate_limits: AuthRateLimits::with_all_policies(
                rate_clock,
                LOGIN_RATE_POLICY,
                BOOTSTRAP_RATE_POLICY,
                test_rate_policy(10, 1, None),
            ),
            ingress: IngressPolicy::direct(false),
        });
        let state = ApiState {
            store,
            durable_ledger_poll_interval: DURABLE_LEDGER_POLL_INTERVAL,
            broadcast_hints_enabled: true,
            auth: Some(auth),
            reply: Some(Arc::new(ReplyExecutor::new(Arc::new(
                LocalFallbackProvider::new(),
            )))),
            sse_capacity: SseCapacity::production(),
        };
        let app = build_authenticated_app(state).layer(MockConnectInfo(test_peer()));

        let invalid = app
            .clone()
            .oneshot(member_setup_request(
                "/api/v1/auth/member-setup",
                "invalid",
                "Member-password-2026",
            ))
            .await
            .unwrap();
        assert_problem(
            invalid,
            StatusCode::UNAUTHORIZED,
            "invalid_member_setup_token",
        )
        .await;

        let limited = app
            .oneshot(member_setup_request(
                "/api/auth/member-setup",
                "also-invalid",
                "Member-password-2026",
            ))
            .await
            .unwrap();
        assert_eq!(limited.headers()[header::RETRY_AFTER], "60");
        assert_eq!(limited.headers()[header::CACHE_CONTROL], "no-store");
        assert_problem(
            limited,
            StatusCode::TOO_MANY_REQUESTS,
            "member_setup_rate_limited",
        )
        .await;
    }

    #[tokio::test]
    async fn member_login_succeeds_while_other_invalid_credentials_remain_indistinguishable() {
        let fixture = configured_auth_test_app("login-equivalence", LOGIN_RATE_POLICY).await;
        let mut failures = Vec::new();

        failures.push(
            fixture
                .app
                .clone()
                .oneshot(login_request("owner", "Wrong-password-2026"))
                .await
                .unwrap(),
        );
        failures.push(
            fixture
                .app
                .clone()
                .oneshot(login_request("missing-owner", TEST_OWNER_PASSWORD))
                .await
                .unwrap(),
        );

        insert_test_member(&fixture.path, "user-login-member", "member");
        copy_test_password(&fixture.path, "owner", "member");
        let member_login = fixture
            .app
            .clone()
            .oneshot(login_request("member", TEST_OWNER_PASSWORD))
            .await
            .unwrap();
        assert_eq!(member_login.status(), StatusCode::OK);
        assert_eq!(member_login.headers()[header::CACHE_CONTROL], "no-store");
        let member_authentication: AuthenticationResponse = response_json(member_login).await;
        assert_eq!(member_authentication.user.username, "member");
        assert_eq!(member_authentication.user.role, AccountRole::Member);
        insert_test_non_local_owner(&fixture.path);
        copy_test_password(&fixture.path, "owner", "other-owner");
        failures.push(
            fixture
                .app
                .clone()
                .oneshot(login_request("other-owner", TEST_OWNER_PASSWORD))
                .await
                .unwrap(),
        );
        insert_test_disabled_local_owner(&fixture.path);
        copy_test_password(&fixture.path, "owner", "disabled-owner");
        failures.push(
            fixture
                .app
                .clone()
                .oneshot(login_request("disabled-owner", TEST_OWNER_PASSWORD))
                .await
                .unwrap(),
        );
        update_test_user_status(&fixture.path, "disabled");
        failures.push(
            fixture
                .app
                .clone()
                .oneshot(login_request("owner", TEST_OWNER_PASSWORD))
                .await
                .unwrap(),
        );

        let mut expected_headers = None;
        let mut expected_problem = None;
        for response in failures {
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
            assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
            if let Some(expected) = &expected_headers {
                assert_eq!(response.headers(), expected);
            } else {
                expected_headers = Some(response.headers().clone());
            }
            let problem: ProblemDetails = response_json(response).await;
            assert_eq!(problem.code, "invalid_credentials");
            if let Some(expected) = &expected_problem {
                assert_eq!(&problem, expected);
            } else {
                expected_problem = Some(problem);
            }
        }

        update_test_user_status(&fixture.path, "active");
        let success = fixture
            .app
            .clone()
            .oneshot(login_request("owner", TEST_OWNER_PASSWORD))
            .await
            .unwrap();
        assert_eq!(success.status(), StatusCode::OK);

        fixture.cleanup();
    }

    #[tokio::test]
    async fn account_control_plane_is_idempotent_rotates_sessions_and_isolates_resources() {
        let fixture = configured_auth_test_app("multi-account", LOGIN_RATE_POLICY).await;

        let login = fixture
            .app
            .clone()
            .oneshot(login_request("owner", TEST_OWNER_PASSWORD))
            .await
            .unwrap();
        assert_eq!(login.status(), StatusCode::OK);
        let local_cookie = authentication_cookie_header(login.headers());
        let local_authentication: AuthenticationResponse = response_json(login).await;
        assert_eq!(local_authentication.account_id, AccountId::local().as_str());

        let local_session = fixture
            .app
            .clone()
            .oneshot(
                Request::post("/api/v1/sessions")
                    .header(header::HOST, "zeus.test")
                    .header(header::ORIGIN, "http://zeus.test")
                    .header(header::COOKIE, &local_cookie)
                    .header(CSRF_HEADER, &local_authentication.csrf_token)
                    .header(header::CONTENT_TYPE, "application/json")
                    .header("idempotency-key", "multi-account-local-session")
                    .body(Body::from(
                        r#"{"id":"session-local-account","title":"Local account"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(local_session.status(), StatusCode::CREATED);

        let created = fixture
            .app
            .clone()
            .oneshot(
                Request::post("/api/v1/accounts")
                    .header(header::HOST, "zeus.test")
                    .header(header::ORIGIN, "http://zeus.test")
                    .header(header::COOKIE, &local_cookie)
                    .header(CSRF_HEADER, &local_authentication.csrf_token)
                    .header(header::CONTENT_TYPE, "application/json")
                    .header("idempotency-key", "create-secondary-account")
                    .body(Body::from(r#"{"name":"Secondary"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(created.status(), StatusCode::CREATED);
        assert_eq!(created.headers()[header::CACHE_CONTROL], "no-store");
        let created: CreateAccountResponse = response_json(created).await;
        assert!(!created.replayed);
        assert_eq!(created.account.name, "Secondary");
        assert_eq!(created.account.role, AccountRole::Owner);
        let secondary_account_id = created.account.id;

        let replay = fixture
            .app
            .clone()
            .oneshot(
                Request::post("/api/v1/accounts")
                    .header(header::HOST, "zeus.test")
                    .header(header::ORIGIN, "http://zeus.test")
                    .header(header::COOKIE, &local_cookie)
                    .header(CSRF_HEADER, &local_authentication.csrf_token)
                    .header(header::CONTENT_TYPE, "application/json")
                    .header("idempotency-key", "create-secondary-account")
                    .body(Body::from(r#"{"name":"Secondary"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(replay.status(), StatusCode::OK);
        let replay: CreateAccountResponse = response_json(replay).await;
        assert!(replay.replayed);
        assert_eq!(replay.account.id, secondary_account_id);

        let conflict = fixture
            .app
            .clone()
            .oneshot(
                Request::post("/api/v1/accounts")
                    .header(header::HOST, "zeus.test")
                    .header(header::ORIGIN, "http://zeus.test")
                    .header(header::COOKIE, &local_cookie)
                    .header(CSRF_HEADER, &local_authentication.csrf_token)
                    .header(header::CONTENT_TYPE, "application/json")
                    .header("idempotency-key", "create-secondary-account")
                    .body(Body::from(r#"{"name":"Different"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_problem(conflict, StatusCode::CONFLICT, "idempotency_conflict").await;

        let accounts = fixture
            .app
            .clone()
            .oneshot(
                Request::get("/api/v1/accounts")
                    .header(header::COOKIE, &local_cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(accounts.headers()[header::CACHE_CONTROL], "no-store");
        let accounts: AccountListResponse = response_json(accounts).await;
        assert_eq!(accounts.current_account_id, AccountId::local().as_str());
        assert_eq!(accounts.accounts.len(), 2);
        assert!(
            accounts
                .accounts
                .iter()
                .any(|account| account.id == secondary_account_id)
        );

        let malformed_account_login = fixture
            .app
            .clone()
            .oneshot(
                Request::post("/api/v1/auth/login")
                    .header(header::HOST, "zeus.test")
                    .header(header::ORIGIN, "http://zeus.test")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "username": "owner",
                            "password": TEST_OWNER_PASSWORD,
                            "account_id": "acc_not-canonical!",
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_problem(
            malformed_account_login,
            StatusCode::UNAUTHORIZED,
            "invalid_credentials",
        )
        .await;

        let member = insert_test_member(&fixture.path, "user-account-member", "account-member");
        let denied = fixture
            .app
            .clone()
            .oneshot(
                Request::post("/api/v1/accounts")
                    .header(header::HOST, "zeus.test")
                    .header(header::ORIGIN, "http://zeus.test")
                    .header(header::COOKIE, &member.cookie_header)
                    .header(CSRF_HEADER, &member.csrf_token)
                    .header(header::CONTENT_TYPE, "application/json")
                    .header("idempotency-key", "member-cannot-create-account")
                    .body(Body::from(r#"{"name":"Forbidden"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_problem(denied, StatusCode::FORBIDDEN, "permission_denied").await;

        let missing_account_id =
            AccountId::for_creation(&local_authentication.user.id, "missing-account");
        let missing = fixture
            .app
            .clone()
            .oneshot(
                Request::post("/api/v1/auth/switch-account")
                    .header(header::HOST, "zeus.test")
                    .header(header::ORIGIN, "http://zeus.test")
                    .header(header::COOKIE, &local_cookie)
                    .header(CSRF_HEADER, &local_authentication.csrf_token)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        serde_json::json!({ "account_id": missing_account_id.as_str() })
                            .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_problem(missing, StatusCode::NOT_FOUND, "account_not_found").await;
        let preserved = fixture
            .app
            .clone()
            .oneshot(
                Request::get("/api/v1/overview")
                    .header(header::COOKIE, &local_cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(preserved.status(), StatusCode::OK);

        let switched = fixture
            .app
            .clone()
            .oneshot(
                Request::post("/api/v1/auth/switch-account")
                    .header(header::HOST, "zeus.test")
                    .header(header::ORIGIN, "http://zeus.test")
                    .header(header::COOKIE, &local_cookie)
                    .header(CSRF_HEADER, &local_authentication.csrf_token)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        serde_json::json!({ "account_id": &secondary_account_id }).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(switched.status(), StatusCode::OK);
        let secondary_cookie = authentication_cookie_header(switched.headers());
        assert_ne!(secondary_cookie, local_cookie);
        let secondary_authentication: AuthenticationResponse = response_json(switched).await;
        assert_eq!(secondary_authentication.account_id, secondary_account_id);

        let revoked = fixture
            .app
            .clone()
            .oneshot(
                Request::get("/api/v1/overview")
                    .header(header::COOKIE, &local_cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(revoked.status(), StatusCode::UNAUTHORIZED);

        let status = fixture
            .app
            .clone()
            .oneshot(
                Request::get("/api/v1/auth/status")
                    .header(header::COOKIE, &secondary_cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let status: AuthStatusResponse = response_json(status).await;
        assert!(status.authenticated);
        assert_eq!(
            status.account_id.as_deref(),
            Some(secondary_account_id.as_str())
        );

        let isolated = fixture
            .app
            .clone()
            .oneshot(
                Request::get("/api/v1/sessions")
                    .header(header::COOKIE, &secondary_cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let isolated: serde_json::Value = response_json(isolated).await;
        assert_eq!(isolated, serde_json::json!([]));

        let secondary_session = fixture
            .app
            .clone()
            .oneshot(
                Request::post("/api/v1/sessions")
                    .header(header::HOST, "zeus.test")
                    .header(header::ORIGIN, "http://zeus.test")
                    .header(header::COOKIE, &secondary_cookie)
                    .header(CSRF_HEADER, &secondary_authentication.csrf_token)
                    .header(header::CONTENT_TYPE, "application/json")
                    .header("idempotency-key", "multi-account-secondary-session")
                    .body(Body::from(
                        r#"{"id":"session-secondary-account","title":"Secondary account"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(secondary_session.status(), StatusCode::CREATED);

        let account_login = fixture
            .app
            .clone()
            .oneshot(
                Request::post("/api/v1/auth/login")
                    .header(header::HOST, "zeus.test")
                    .header(header::ORIGIN, "http://zeus.test")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "username": "owner",
                            "password": TEST_OWNER_PASSWORD,
                            "account_id": &secondary_account_id,
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(account_login.status(), StatusCode::OK);
        let account_login: AuthenticationResponse = response_json(account_login).await;
        assert_eq!(account_login.account_id, secondary_account_id);

        fixture.store.readiness().await.unwrap();
        fixture.cleanup();
    }

    #[tokio::test]
    async fn owner_creates_rotates_and_disables_a_member_with_live_sse_revocation() {
        let (app, store, owner, path) = authenticated_file_app("member-lifecycle-http").await;
        let app = app.layer(MockConnectInfo(test_peer()));
        let unsupported_idempotency = app
            .clone()
            .oneshot(
                Request::post("/api/v1/members")
                    .header(header::HOST, "zeus.test")
                    .header(header::ORIGIN, "http://zeus.test")
                    .header(header::COOKIE, &owner.cookie_header)
                    .header(CSRF_HEADER, &owner.csrf_token)
                    .header(header::CONTENT_TYPE, "application/json")
                    .header("idempotency-key", "member-create-is-not-receipted")
                    .body(Body::from(r#"{"username":"member-http"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_problem(
            unsupported_idempotency,
            StatusCode::BAD_REQUEST,
            "idempotency_not_supported",
        )
        .await;

        let concealed_missing_member = app
            .clone()
            .oneshot(
                Request::post("/api/v1/members/user-missing/setup-token")
                    .header(header::HOST, "zeus.test")
                    .header(header::ORIGIN, "http://zeus.test")
                    .header(header::COOKIE, &owner.cookie_header)
                    .header(CSRF_HEADER, &owner.csrf_token)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from("not-json"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_problem(
            concealed_missing_member,
            StatusCode::NOT_FOUND,
            "member_not_found",
        )
        .await;

        let last_owner = app
            .clone()
            .oneshot(
                Request::patch(format!("/api/v1/members/{}", owner.user_id))
                    .header(header::HOST, "zeus.test")
                    .header(header::ORIGIN, "http://zeus.test")
                    .header(header::COOKIE, &owner.cookie_header)
                    .header(CSRF_HEADER, &owner.csrf_token)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "expected_revision": owner.authz.membership_revision.get(),
                            "role": "member",
                            "status": "disabled"
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_problem(last_owner, StatusCode::CONFLICT, "last_account_owner").await;

        let create = app
            .clone()
            .oneshot(
                Request::post("/api/v1/members")
                    .header(header::HOST, "zeus.test")
                    .header(header::ORIGIN, "http://zeus.test")
                    .header(header::COOKIE, &owner.cookie_header)
                    .header(CSRF_HEADER, &owner.csrf_token)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(r#"{"username":"member-http"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(create.status(), StatusCode::CREATED);

        assert_eq!(create.headers()[header::CACHE_CONTROL], "no-store");
        let created: MemberSetupTokenResponse = response_json(create).await;
        assert_eq!(created.member.role, AccountRole::Member);
        assert!(created.member.setup_required);

        let pending_login = app
            .clone()
            .oneshot(login_request("member-http", "Wrong-password-2026"))
            .await
            .unwrap();
        let missing_login = app
            .clone()
            .oneshot(login_request("missing-member-http", "Wrong-password-2026"))
            .await
            .unwrap();
        assert_eq!(pending_login.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(missing_login.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(pending_login.headers(), missing_login.headers());
        let pending_problem: ProblemDetails = response_json(pending_login).await;
        let missing_problem: ProblemDetails = response_json(missing_login).await;
        assert_eq!(pending_problem.code, "invalid_credentials");
        assert_eq!(pending_problem, missing_problem);

        let expired_at = "2020-01-01T00:00:00.000Z";
        let mut connection = Connection::open(&path).unwrap();
        connection.busy_timeout(Duration::from_secs(1)).unwrap();
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM auth_sessions WHERE user_id = ?1",
                    [&created.member.user_id],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            0
        );
        let credential_before = connection
            .query_row(
                "SELECT status, password_hash FROM users WHERE id = ?1",
                [&created.member.user_id],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .unwrap();
        let transaction = connection.transaction().unwrap();
        let setup_row = transaction
            .query_row(
                r#"SELECT token_digest, account_id, user_id, created_by_user_id
                   FROM member_setup_tokens WHERE user_id = ?1"#,
                [&created.member.user_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                    ))
                },
            )
            .unwrap();
        assert_eq!(
            transaction
                .execute(
                    "DELETE FROM member_setup_tokens WHERE user_id = ?1",
                    [&created.member.user_id,]
                )
                .unwrap(),
            1
        );
        transaction
            .execute(
                r#"INSERT INTO member_setup_tokens(
                       token_digest, account_id, user_id, created_by_user_id,
                       created_at, expires_at
                   ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)"#,
                params![
                    setup_row.0,
                    setup_row.1,
                    setup_row.2,
                    setup_row.3,
                    "2019-01-01T00:00:00.000Z",
                    expired_at,
                ],
            )
            .unwrap();
        transaction.commit().unwrap();
        drop(connection);

        let expired_setup = app
            .clone()
            .oneshot(member_setup_request(
                "/api/v1/auth/member-setup",
                &created.setup_token,
                "Member-password-2026",
            ))
            .await
            .unwrap();
        assert_problem(
            expired_setup,
            StatusCode::UNAUTHORIZED,
            "invalid_member_setup_token",
        )
        .await;
        let connection = Connection::open(&path).unwrap();
        connection.busy_timeout(Duration::from_secs(1)).unwrap();
        let credential_after = connection
            .query_row(
                "SELECT status, password_hash FROM users WHERE id = ?1",
                [&created.member.user_id],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .unwrap();
        assert_eq!(credential_after, credential_before);
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM auth_sessions WHERE user_id = ?1",
                    [&created.member.user_id],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            0
        );
        drop(connection);

        let expired_list = app
            .clone()
            .oneshot(
                Request::get("/api/v1/members")
                    .header(header::COOKIE, &owner.cookie_header)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let expired_members: AccountMemberPage = response_json(expired_list).await;
        assert!(
            expired_members
                .members
                .iter()
                .any(|member| member.user_id == created.member.user_id),
            "expired setup member missing from owner list: {:?}",
            expired_members.members
        );
        let expired_member = expired_members
            .members
            .into_iter()
            .find(|member| member.user_id == created.member.user_id)
            .unwrap();
        assert!(expired_member.setup_required);
        assert_eq!(
            expired_member.setup_token_expires_at.as_deref(),
            Some(expired_at)
        );

        let pending_disable = app
            .clone()
            .oneshot(
                Request::patch(format!("/api/v1/members/{}", created.member.user_id))
                    .header(header::HOST, "zeus.test")
                    .header(header::ORIGIN, "http://zeus.test")
                    .header(header::COOKIE, &owner.cookie_header)
                    .header(CSRF_HEADER, &owner.csrf_token)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "expected_revision": expired_member.revision,
                            "status": "disabled"
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(pending_disable.status(), StatusCode::OK);
        let pending_disabled: UpdateMemberResponse = response_json(pending_disable).await;
        assert_eq!(pending_disabled.member.status, AccountStatus::Disabled);
        assert!(pending_disabled.member.setup_required);
        assert!(pending_disabled.member.setup_token_expires_at.is_none());

        let pending_enable = app
            .clone()
            .oneshot(
                Request::patch(format!("/api/v1/members/{}", created.member.user_id))
                    .header(header::HOST, "zeus.test")
                    .header(header::ORIGIN, "http://zeus.test")
                    .header(header::COOKIE, &owner.cookie_header)
                    .header(CSRF_HEADER, &owner.csrf_token)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "expected_revision": pending_disabled.member.revision,
                            "status": "active"
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(pending_enable.status(), StatusCode::OK);
        let pending_enabled: UpdateMemberResponse = response_json(pending_enable).await;
        assert_eq!(pending_enabled.member.status, AccountStatus::Active);
        assert!(pending_enabled.member.setup_required);
        assert!(pending_enabled.member.setup_token_expires_at.is_none());

        let rotate = app
            .clone()
            .oneshot(
                Request::post(format!(
                    "/api/v1/members/{}/setup-token",
                    created.member.user_id
                ))
                .header(header::HOST, "zeus.test")
                .header(header::ORIGIN, "http://zeus.test")
                .header(header::COOKIE, &owner.cookie_header)
                .header(CSRF_HEADER, &owner.csrf_token)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "expected_revision": pending_enabled.member.revision
                    })
                    .to_string(),
                ))
                .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(rotate.status(), StatusCode::OK);
        let first_rotation: MemberSetupTokenResponse = response_json(rotate).await;
        assert_ne!(first_rotation.setup_token, created.setup_token);
        assert_eq!(
            first_rotation.member.revision,
            pending_enabled.member.revision
        );

        let recovery_rotation = app
            .clone()
            .oneshot(
                Request::post(format!(
                    "/api/v1/members/{}/setup-token",
                    created.member.user_id
                ))
                .header(header::HOST, "zeus.test")
                .header(header::ORIGIN, "http://zeus.test")
                .header(header::COOKIE, &owner.cookie_header)
                .header(CSRF_HEADER, &owner.csrf_token)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "expected_revision": pending_enabled.member.revision
                    })
                    .to_string(),
                ))
                .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(recovery_rotation.status(), StatusCode::OK);
        let rotated: MemberSetupTokenResponse = response_json(recovery_rotation).await;
        assert_ne!(rotated.setup_token, first_rotation.setup_token);
        assert_eq!(rotated.member.revision, pending_enabled.member.revision);

        let mut unsupported_setup = member_setup_request(
            "/api/v1/auth/member-setup",
            &rotated.setup_token,
            "Member-password-2026",
        );
        unsupported_setup.headers_mut().insert(
            "idempotency-key",
            HeaderValue::from_static("member-setup-is-one-time"),
        );
        let unsupported_setup = app.clone().oneshot(unsupported_setup).await.unwrap();
        assert_problem(
            unsupported_setup,
            StatusCode::BAD_REQUEST,
            "idempotency_not_supported",
        )
        .await;

        let stale_setup = app
            .clone()
            .oneshot(member_setup_request(
                "/api/v1/auth/member-setup",
                &created.setup_token,
                "Member-password-2026",
            ))
            .await
            .unwrap();
        assert_problem(
            stale_setup,
            StatusCode::UNAUTHORIZED,
            "invalid_member_setup_token",
        )
        .await;

        let setup = app
            .clone()
            .oneshot(member_setup_request(
                "/api/auth/member-setup",
                &rotated.setup_token,
                "Member-password-2026",
            ))
            .await
            .unwrap();
        assert_eq!(setup.status(), StatusCode::OK);
        assert_eq!(setup.headers()[header::CACHE_CONTROL], "no-store");
        let member_cookie = authentication_cookie_header(setup.headers());
        let member_auth: AuthenticationResponse = response_json(setup).await;
        assert_eq!(member_auth.user.role, AccountRole::Member);
        assert_eq!(member_auth.user.username, "member-http");

        let replayed_setup = app
            .clone()
            .oneshot(member_setup_request(
                "/api/v1/auth/member-setup",
                &rotated.setup_token,
                "Different-member-password-2026",
            ))
            .await
            .unwrap();
        assert_problem(
            replayed_setup,
            StatusCode::UNAUTHORIZED,
            "invalid_member_setup_token",
        )
        .await;

        let completed_rotation = app
            .clone()
            .oneshot(
                Request::post(format!(
                    "/api/v1/members/{}/setup-token",
                    created.member.user_id
                ))
                .header(header::HOST, "zeus.test")
                .header(header::ORIGIN, "http://zeus.test")
                .header(header::COOKIE, &owner.cookie_header)
                .header(CSRF_HEADER, &owner.csrf_token)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::json!({ "expected_revision": rotated.member.revision }).to_string(),
                ))
                .unwrap(),
            )
            .await
            .unwrap();
        assert_problem(
            completed_rotation,
            StatusCode::CONFLICT,
            "member_setup_not_pending",
        )
        .await;

        let overview = app
            .clone()
            .oneshot(
                Request::get("/api/v1/overview")
                    .header(header::COOKIE, &member_cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(overview.status(), StatusCode::OK);

        let member_admin = app
            .clone()
            .oneshot(
                Request::get("/api/v1/members?limit=not-a-number")
                    .header(header::COOKIE, &member_cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_problem(member_admin, StatusCode::FORBIDDEN, "permission_denied").await;

        let member_audit = app
            .clone()
            .oneshot(
                Request::get("/api/v1/audit/events?limit=not-a-number")
                    .header(header::COOKIE, &member_cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_problem(member_audit, StatusCode::FORBIDDEN, "permission_denied").await;

        let member_mutation = app
            .clone()
            .oneshot(
                Request::post("/api/v1/members")
                    .header(header::HOST, "zeus.test")
                    .header(header::ORIGIN, "http://zeus.test")
                    .header(header::COOKIE, &member_cookie)
                    .header(CSRF_HEADER, &member_auth.csrf_token)
                    .header(header::CONTENT_TYPE, "application/json")
                    .header("idempotency-key", "must-not-mask-member-forbidden")
                    .body(Body::from(r#"{"username":"nested-member"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_problem(member_mutation, StatusCode::FORBIDDEN, "permission_denied").await;

        let approval = app
            .clone()
            .oneshot(
                Request::post(format!(
                    "/api/v1/runs/{DEMO_RUN_ID}/approvals/APR-901/decision"
                ))
                .header(header::HOST, "zeus.test")
                .header(header::ORIGIN, "http://zeus.test")
                .header(header::COOKIE, &member_cookie)
                .header(CSRF_HEADER, &member_auth.csrf_token)
                .header(header::CONTENT_TYPE, "application/json")
                .header("idempotency-key", "member-cannot-approve")
                .body(Body::from(r#"{"decision":"approve"}"#))
                .unwrap(),
            )
            .await
            .unwrap();
        assert_problem(approval, StatusCode::FORBIDDEN, "permission_denied").await;

        let sse = app
            .clone()
            .oneshot(
                Request::get("/api/v1/sessions/session-ZR-1842/events?after=2")
                    .header(header::COOKIE, &member_cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(sse.status(), StatusCode::OK);
        let mut sse_body = sse.into_body();
        let opened = tokio::time::timeout(Duration::from_secs(1), sse_body.frame())
            .await
            .expect("member SSE should open immediately")
            .expect("member SSE should produce an opening frame")
            .expect("member SSE opening frame should be valid");
        assert!(
            String::from_utf8(opened.into_data().unwrap().to_vec())
                .unwrap()
                .contains("stream-open")
        );

        let list = app
            .clone()
            .oneshot(
                Request::get("/api/v1/members")
                    .header(header::COOKIE, &owner.cookie_header)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let members: AccountMemberPage = response_json(list).await;
        let member = members
            .members
            .into_iter()
            .find(|member| member.user_id == created.member.user_id)
            .unwrap();
        let stale_disable = app
            .clone()
            .oneshot(
                Request::patch(format!("/api/v1/members/{}", member.user_id))
                    .header(header::HOST, "zeus.test")
                    .header(header::ORIGIN, "http://zeus.test")
                    .header(header::COOKIE, &owner.cookie_header)
                    .header(CSRF_HEADER, &owner.csrf_token)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "expected_revision": member.revision + 1,
                            "status": "disabled"
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_problem(
            stale_disable,
            StatusCode::CONFLICT,
            "membership_revision_conflict",
        )
        .await;

        let disable = app
            .clone()
            .oneshot(
                Request::patch(format!("/api/v1/members/{}", member.user_id))
                    .header(header::HOST, "zeus.test")
                    .header(header::ORIGIN, "http://zeus.test")
                    .header(header::COOKIE, &owner.cookie_header)
                    .header(CSRF_HEADER, &owner.csrf_token)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "expected_revision": member.revision,
                            "status": "disabled"
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(disable.status(), StatusCode::OK);
        let disabled: UpdateMemberResponse = response_json(disable).await;
        assert_eq!(disabled.member.status, AccountStatus::Disabled);

        let ended = tokio::time::timeout(Duration::from_secs(3), sse_body.frame())
            .await
            .expect("member disable should close SSE by the durable auth poll");
        assert!(ended.is_none(), "disabled member SSE emitted another frame");
        let status = app
            .clone()
            .oneshot(
                Request::get("/api/v1/auth/status")
                    .header(header::COOKIE, &member_cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let status: AuthStatusResponse = response_json(status).await;
        assert!(!status.authenticated);

        drop(sse_body);
        drop(app);
        drop(store);
        cleanup_test_database(&path);
    }

    #[tokio::test]
    async fn owner_reads_exports_configures_and_checkpoints_account_audit_history() {
        let (app, store, owner, path) = authenticated_file_app("account-audit-http").await;
        let app = app.layer(MockConnectInfo(test_peer()));

        let create = app
            .clone()
            .oneshot(
                Request::post("/api/v1/members")
                    .header(header::HOST, "zeus.test")
                    .header(header::ORIGIN, "http://zeus.test")
                    .header(header::COOKIE, &owner.cookie_header)
                    .header(CSRF_HEADER, &owner.csrf_token)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(r#"{"username":"audit-member"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(create.status(), StatusCode::CREATED);

        // Keep the HTTP export on its real multi-page path (100 rows/page)
        // without weakening the production page size just for a test.
        for index in 0..100 {
            let user_id = UserId::generate().unwrap();
            store
                .create_member(
                    &owner.authz,
                    user_id.as_str().to_owned(),
                    format!("audit-member-{index:03}"),
                )
                .await
                .unwrap();
        }

        let first_page = app
            .clone()
            .oneshot(
                Request::get("/api/v1/audit/events?limit=1")
                    .header(header::COOKIE, &owner.cookie_header)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(first_page.status(), StatusCode::OK);
        assert_eq!(first_page.headers()[header::CACHE_CONTROL], "no-store");
        let first_page: AccountAuditEventPage = response_json(first_page).await;
        assert_eq!(first_page.events.len(), 1);
        assert_eq!(first_page.events[0].action, "member.created");
        assert_eq!(first_page.events[0].outcome, "succeeded");
        assert_eq!(
            first_page.events[0].target_user_id.as_deref(),
            Some(first_page.events[0].target_id.as_str())
        );
        assert_eq!(first_page.state.detailed_rows, 101);

        let policy = app
            .clone()
            .oneshot(
                Request::get("/api/v1/audit/policy")
                    .header(header::COOKIE, &owner.cookie_header)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(policy.status(), StatusCode::OK);
        assert_eq!(policy.headers()[header::CACHE_CONTROL], "no-store");
        let policy: AccountAuditPolicyResponse = response_json(policy).await;

        let updated_policy = app
            .clone()
            .oneshot(
                Request::put("/api/v1/audit/policy")
                    .header(header::HOST, "zeus.test")
                    .header(header::ORIGIN, "http://zeus.test")
                    .header(header::COOKIE, &owner.cookie_header)
                    .header(CSRF_HEADER, &owner.csrf_token)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "detail_rows": policy.detail_rows,
                            "legal_hold": policy.legal_hold,
                            "archive_required": policy.archive_required,
                            "expected_revision": policy.revision,
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(updated_policy.status(), StatusCode::OK);
        assert_eq!(updated_policy.headers()[header::CACHE_CONTROL], "no-store");
        let updated_policy: AccountAuditPolicyResponse = response_json(updated_policy).await;
        assert_eq!(updated_policy.revision, policy.revision + 1);

        let stale_policy = app
            .clone()
            .oneshot(
                Request::put("/api/v1/audit/policy")
                    .header(header::HOST, "zeus.test")
                    .header(header::ORIGIN, "http://zeus.test")
                    .header(header::COOKIE, &owner.cookie_header)
                    .header(CSRF_HEADER, &owner.csrf_token)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "detail_rows": policy.detail_rows,
                            "legal_hold": policy.legal_hold,
                            "archive_required": policy.archive_required,
                            "expected_revision": policy.revision,
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_problem(
            stale_policy,
            StatusCode::CONFLICT,
            "audit_policy_revision_conflict",
        )
        .await;

        let events = app
            .clone()
            .oneshot(
                Request::get("/api/v1/audit/events?limit=100")
                    .header(header::COOKIE, &owner.cookie_header)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let events: AccountAuditEventPage = response_json(events).await;
        assert_eq!(events.events[0].action, "audit.policy_updated");
        assert!(
            events
                .events
                .iter()
                .any(|event| event.action == "member.created")
        );
        let checkpoint_event = events.events[0].clone();
        let archive_revision = events.state.archive.revision;

        let export = app
            .clone()
            .oneshot(
                Request::get("/api/v1/audit/export")
                    .header(header::COOKIE, &owner.cookie_header)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(export.status(), StatusCode::OK);
        assert_eq!(export.headers()[header::CACHE_CONTROL], "no-store");
        assert_eq!(
            export.headers()[header::CONTENT_TYPE],
            "application/x-ndjson"
        );
        assert_eq!(
            export.headers()[header::CONTENT_DISPOSITION],
            "attachment; filename=zeus-account-audit.ndjson"
        );
        let export_bytes = export.into_body().collect().await.unwrap().to_bytes();
        assert!(export_bytes.len() < ACCOUNT_AUDIT_EXPORT_MAX_BYTES);
        assert_eq!(export_bytes.last(), Some(&b'\n'));
        let mut export_lines = export_bytes
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty());
        let manifest = serde_json::from_slice::<AccountAuditExportManifest>(
            export_lines.next().expect("export manifest line"),
        )
        .unwrap();
        assert_eq!(manifest.kind, ACCOUNT_AUDIT_EXPORT_MANIFEST_KIND);
        assert_eq!(manifest.schema_version, ACCOUNT_AUDIT_EXPORT_SCHEMA_VERSION);
        assert_eq!(manifest.event_schema, ACCOUNT_AUDIT_EVENT_SCHEMA);
        assert_eq!(manifest.rollup, events.state.rollup);
        assert_eq!(manifest.snapshot_head_sequence, events.events[0].sequence);
        assert_eq!(manifest.snapshot_event_count, events.state.detailed_rows);
        assert_eq!(manifest.detailed_event_count, events.state.detailed_rows);
        let exported = export_lines
            .map(|line| serde_json::from_slice::<AccountAuditEvent>(line).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(exported.len() as u64, events.state.detailed_rows);
        assert_eq!(exported.first(), events.events.first());
        assert!(exported.windows(2).all(|window| {
            window[0].sequence.checked_sub(1) == Some(window[1].sequence)
                && window[0].previous_hash == window[1].event_hash
        }));

        let checkpoint = app
            .clone()
            .oneshot(
                Request::post("/api/v1/audit/archive/checkpoint")
                    .header(header::HOST, "zeus.test")
                    .header(header::ORIGIN, "http://zeus.test")
                    .header(header::COOKIE, &owner.cookie_header)
                    .header(CSRF_HEADER, &owner.csrf_token)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "expected_revision": archive_revision,
                            "through_sequence": checkpoint_event.sequence,
                            "event_hash": checkpoint_event.event_hash,
                            "archive_reference": "test://zeus/account-audit/http",
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(checkpoint.status(), StatusCode::OK);
        assert_eq!(checkpoint.headers()[header::CACHE_CONTROL], "no-store");
        let checkpoint: AccountAuditCheckpointResponse = response_json(checkpoint).await;
        assert_eq!(
            checkpoint.archive.through_sequence,
            checkpoint_event.sequence
        );
        assert_eq!(
            checkpoint.archive.archive_reference.as_deref(),
            Some("test://zeus/account-audit/http")
        );
        assert_eq!(checkpoint.archive, checkpoint.state.archive);

        let stale_checkpoint = app
            .clone()
            .oneshot(
                Request::post("/api/v1/audit/archive/checkpoint")
                    .header(header::HOST, "zeus.test")
                    .header(header::ORIGIN, "http://zeus.test")
                    .header(header::COOKIE, &owner.cookie_header)
                    .header(CSRF_HEADER, &owner.csrf_token)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "expected_revision": archive_revision,
                            "through_sequence": checkpoint_event.sequence,
                            "event_hash": checkpoint_event.event_hash,
                            "archive_reference": "test://zeus/account-audit/stale",
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_problem(
            stale_checkpoint,
            StatusCode::CONFLICT,
            "audit_checkpoint_conflict",
        )
        .await;

        drop(app);
        drop(store);
        cleanup_test_database(&path);
    }

    #[tokio::test]
    async fn sse_actor_capacity_is_held_by_the_response_body_and_released_on_drop() {
        let app = test_app().await;
        let mut streams = Vec::new();
        for index in 0..SSE_ACTOR_CONNECTION_LIMIT {
            let uri = if index % 2 == 0 {
                format!("/api/v1/runs/{DEMO_RUN_ID}/events?after=8")
            } else {
                format!(
                    "/api/v1/sessions/{}/events?after=0",
                    protocol::DEMO_SESSION_ID
                )
            };
            let response = app
                .clone()
                .oneshot(Request::get(uri).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            streams.push(response);
        }

        let limited = app
            .clone()
            .oneshot(
                Request::get(format!("/api/v1/runs/{DEMO_RUN_ID}/events?after=8"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(limited.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(limited.headers()[header::RETRY_AFTER], "2");
        let problem: ProblemDetails = response_json(limited).await;
        assert_eq!(problem.code, "sse_capacity_exceeded");

        drop(streams.pop());
        let reopened = app
            .oneshot(
                Request::get(format!("/api/v1/runs/{DEMO_RUN_ID}/events?after=8"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(reopened.status(), StatusCode::OK);
    }

    #[derive(Clone, Copy)]
    enum IndeterminateFailure {
        Known,
        SecretUnavailable,
        Timeout,
        Transport,
        Panic,
    }

    struct IndeterminateProvider {
        metadata: ProviderMetadata,
        failure: IndeterminateFailure,
    }

    impl IndeterminateProvider {
        fn new(failure: IndeterminateFailure) -> Self {
            Self {
                metadata: ProviderMetadata {
                    provider_id: "test-indeterminate-provider".into(),
                    model: Some("test-model".into()),
                    reply_kind: ReplyKind::Model,
                },
                failure,
            }
        }
    }

    impl ReplyProvider for IndeterminateProvider {
        fn metadata(&self) -> &ProviderMetadata {
            &self.metadata
        }

        fn reply(&self, _request: ReplyRequest) -> ReplyFuture<'_> {
            let failure = self.failure;
            Box::pin(async move {
                Err(match failure {
                    IndeterminateFailure::Known => {
                        ProviderError::InvalidRequest("known provider rejection")
                    }
                    IndeterminateFailure::SecretUnavailable => ProviderError::SecretUnavailable,
                    IndeterminateFailure::Timeout => ProviderError::Timeout,
                    IndeterminateFailure::Transport => ProviderError::Transport,
                    IndeterminateFailure::Panic => {
                        panic!("test provider panic must be isolated")
                    }
                })
            })
        }
    }

    struct CountingProvider {
        metadata: ProviderMetadata,
        calls: Arc<AtomicUsize>,
    }

    struct RecordingProvider {
        metadata: ProviderMetadata,
        requests: Arc<StdMutex<Vec<ReplyRequest>>>,
    }

    struct StreamingProvider {
        metadata: ProviderMetadata,
        first_delta: String,
        second_delta: String,
    }

    struct TruncatedStreamingProvider {
        metadata: ProviderMetadata,
        delta: String,
    }

    struct CancelAwareStreamingProvider {
        metadata: ProviderMetadata,
        prefix: String,
        blocked: Arc<tokio::sync::Barrier>,
        dropped: Arc<AtomicUsize>,
    }

    struct StreamDropCounter(Arc<AtomicUsize>);

    impl Drop for StreamDropCounter {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::Release);
        }
    }

    struct ToolThenFinalProvider {
        metadata: ProviderMetadata,
        requests: Arc<StdMutex<Vec<ReplyRequest>>>,
    }

    struct TodoThenFinalProvider {
        metadata: ProviderMetadata,
        requests: Arc<StdMutex<Vec<ReplyRequest>>>,
    }

    struct SpawnListThenFinalProvider {
        metadata: ProviderMetadata,
        requests: Arc<StdMutex<Vec<ReplyRequest>>>,
    }

    struct GoalReadCreateThenFinalProvider {
        metadata: ProviderMetadata,
        requests: Arc<StdMutex<Vec<ReplyRequest>>>,
    }

    #[derive(Clone, Copy)]
    enum GoalRoundTerminal {
        FinalAtLimit,
        KnownProviderFailure,
    }

    struct GoalCreateThenRoundTerminalProvider {
        metadata: ProviderMetadata,
        requests: Arc<StdMutex<Vec<ReplyRequest>>>,
        terminal: GoalRoundTerminal,
    }

    struct WorkspaceSearchThenFinalProvider {
        metadata: ProviderMetadata,
        requests: Arc<StdMutex<Vec<ReplyRequest>>>,
    }

    struct WorkspaceFindThenFinalProvider {
        metadata: ProviderMetadata,
        requests: Arc<StdMutex<Vec<ReplyRequest>>>,
    }

    struct WorkspaceReplaceThenFinalProvider {
        metadata: ProviderMetadata,
        requests: Arc<StdMutex<Vec<ReplyRequest>>>,
    }

    struct WorkspaceCreateThenFinalProvider {
        metadata: ProviderMetadata,
        requests: Arc<StdMutex<Vec<ReplyRequest>>>,
    }

    struct WorkspaceInsertThenFinalProvider {
        metadata: ProviderMetadata,
        requests: Arc<StdMutex<Vec<ReplyRequest>>>,
    }

    struct TerminalOpenSendThenFinalProvider {
        metadata: ProviderMetadata,
        requests: Arc<StdMutex<Vec<ReplyRequest>>>,
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    enum RecordedTerminalAction {
        Spawn(BackendSpawnRequest),
        Send {
            session_id: String,
            request: TerminalSendRequest,
        },
        Close {
            session_id: String,
        },
    }

    struct RecordingTerminalBackend {
        actions: Arc<StdMutex<Vec<RecordedTerminalAction>>>,
        hang_send: bool,
    }

    struct RecordingTerminalSession {
        session_id: String,
        actions: Arc<StdMutex<Vec<RecordedTerminalAction>>>,
        hang_send: bool,
    }

    impl TerminalBackend for RecordingTerminalBackend {
        fn backend_type(&self) -> &str {
            "test-isolated"
        }

        fn spawn(
            &self,
            request: BackendSpawnRequest,
        ) -> TerminalFuture<'_, Arc<dyn TerminalBackendSession>> {
            self.actions
                .lock()
                .unwrap()
                .push(RecordedTerminalAction::Spawn(request.clone()));
            let session: Arc<dyn TerminalBackendSession> = Arc::new(RecordingTerminalSession {
                session_id: request.session_id,
                actions: Arc::clone(&self.actions),
                hang_send: self.hang_send,
            });
            Box::pin(async move { Ok(session) })
        }
    }

    impl TerminalBackendSession for RecordingTerminalSession {
        fn snapshot(&self) -> TerminalFuture<'_, TerminalStatus> {
            Box::pin(async { Ok(TerminalStatus::Running) })
        }

        fn send(&self, request: TerminalSendRequest) -> TerminalFuture<'_, TerminalSendResult> {
            self.actions
                .lock()
                .unwrap()
                .push(RecordedTerminalAction::Send {
                    session_id: self.session_id.clone(),
                    request,
                });
            if self.hang_send {
                return Box::pin(std::future::pending());
            }
            Box::pin(async {
                Ok(TerminalSendResult {
                    viewport: "zeus ready\n".into(),
                    wait_reason: TerminalWaitReason::InferredIdle,
                    status: TerminalStatus::Running,
                    truncated: false,
                })
            })
        }

        fn read(&self, _request: TerminalReadRequest) -> TerminalFuture<'_, TerminalReadResult> {
            Box::pin(async {
                Ok(TerminalReadResult {
                    text: "zeus ready\n".into(),
                    total_lines: 1,
                    line_begin: 0,
                    line_end: 1,
                    truncated: false,
                })
            })
        }

        fn signal(&self, _signal: TerminalSignal) -> TerminalFuture<'_, TerminalStatus> {
            Box::pin(async { Ok(TerminalStatus::Running) })
        }

        fn close(&self) -> TerminalFuture<'_, ()> {
            self.actions
                .lock()
                .unwrap()
                .push(RecordedTerminalAction::Close {
                    session_id: self.session_id.clone(),
                });
            Box::pin(async { Ok(()) })
        }
    }

    const TEST_WORKSPACE_READ_FILE_TOOL_NAME: &str = "workspace_read_file";
    const TEST_WORKSPACE_READ_LINES_TOOL_NAME: &str = "workspace_read_lines";
    const TEST_WORKSPACE_LIST_DIRECTORY_TOOL_NAME: &str = "workspace_list_directory";
    const TEST_WORKSPACE_FIND_PATHS_TOOL_NAME: &str = "workspace_find_paths";
    const TEST_WORKSPACE_SEARCH_TEXT_TOOL_NAME: &str = "workspace_search_text";
    const TEST_WORKSPACE_REPLACE_TEXT_TOOL_NAME: &str = "workspace_replace_text";
    const TEST_WORKSPACE_CREATE_FILE_TOOL_NAME: &str = "workspace_create_file";
    const TEST_WORKSPACE_INSERT_TEXT_TOOL_NAME: &str = "workspace_insert_text";
    const TEST_TERMINAL_OPEN_TOOL_NAME: &str = "terminal_open";
    const TEST_TERMINAL_SEND_TOOL_NAME: &str = "terminal_send";
    const TEST_TERMINAL_READ_TOOL_NAME: &str = "terminal_read";
    const TEST_TERMINAL_SIGNAL_TOOL_NAME: &str = "terminal_signal";
    const TEST_TERMINAL_CLOSE_TOOL_NAME: &str = "terminal_close";
    const TEST_TERMINAL_LIST_TOOL_NAME: &str = "terminal_list";
    static WORKSPACE_DISCOVERY_AGENT_TEST_LOCK: tokio::sync::Mutex<()> =
        tokio::sync::Mutex::const_new(());

    struct HistoryThenToolProvider {
        metadata: ProviderMetadata,
        requests: Arc<StdMutex<Vec<ReplyRequest>>>,
    }

    impl RecordingProvider {
        fn new(requests: Arc<StdMutex<Vec<ReplyRequest>>>) -> Self {
            Self {
                metadata: ProviderMetadata {
                    provider_id: "test-recording-provider".into(),
                    model: Some("test-model".into()),
                    reply_kind: ReplyKind::Model,
                },
                requests,
            }
        }
    }

    impl ReplyProvider for RecordingProvider {
        fn metadata(&self) -> &ProviderMetadata {
            &self.metadata
        }

        fn reply(&self, request: ReplyRequest) -> ReplyFuture<'_> {
            let call = {
                let mut requests = self.requests.lock().unwrap();
                requests.push(request);
                requests.len()
            };
            let provider = self.metadata.clone();
            Box::pin(async move {
                Ok(ReplyResponse {
                    output: ReplyOutput::Final {
                        content: format!("durable answer {call}"),
                    },
                    finish_reason: Some("stop".into()),
                    provider,
                })
            })
        }
    }

    impl StreamingProvider {
        fn new(first_delta: String, second_delta: String) -> Self {
            Self {
                metadata: ProviderMetadata {
                    provider_id: "test-streaming-provider".into(),
                    model: Some("test-model".into()),
                    reply_kind: ReplyKind::Model,
                },
                first_delta,
                second_delta,
            }
        }

        fn response(&self) -> ReplyResponse {
            ReplyResponse {
                output: ReplyOutput::Final {
                    content: format!("{}{}", self.first_delta, self.second_delta),
                },
                finish_reason: Some("stop".into()),
                provider: self.metadata.clone(),
            }
        }
    }

    impl ReplyProvider for StreamingProvider {
        fn metadata(&self) -> &ProviderMetadata {
            &self.metadata
        }

        fn reply(&self, _request: ReplyRequest) -> ReplyFuture<'_> {
            let response = self.response();
            Box::pin(async move { Ok(response) })
        }

        fn stream_reply(&self, _request: ReplyRequest) -> llm::ReplyStream<'_> {
            Box::pin(futures_util::stream::iter(vec![
                Ok(ReplyStreamEvent::TextDelta(self.first_delta.clone())),
                Ok(ReplyStreamEvent::TextDelta(self.second_delta.clone())),
                Ok(ReplyStreamEvent::Completed(self.response())),
            ]))
        }
    }

    impl TruncatedStreamingProvider {
        fn new(delta: String) -> Self {
            Self {
                metadata: ProviderMetadata {
                    provider_id: "test-truncated-streaming-provider".into(),
                    model: Some("test-model".into()),
                    reply_kind: ReplyKind::Model,
                },
                delta,
            }
        }
    }

    impl ReplyProvider for TruncatedStreamingProvider {
        fn metadata(&self) -> &ProviderMetadata {
            &self.metadata
        }

        fn reply(&self, _request: ReplyRequest) -> ReplyFuture<'_> {
            Box::pin(async { Err(ProviderError::Transport) })
        }

        fn stream_reply(&self, _request: ReplyRequest) -> llm::ReplyStream<'_> {
            Box::pin(futures_util::stream::iter(vec![
                Ok(ReplyStreamEvent::TextDelta(self.delta.clone())),
                Err(ProviderError::Transport),
            ]))
        }
    }

    impl CancelAwareStreamingProvider {
        fn new(
            prefix: String,
            blocked: Arc<tokio::sync::Barrier>,
            dropped: Arc<AtomicUsize>,
        ) -> Self {
            Self {
                metadata: ProviderMetadata {
                    provider_id: "test-cancel-aware-streaming-provider".into(),
                    model: Some("test-model".into()),
                    reply_kind: ReplyKind::Model,
                },
                prefix,
                blocked,
                dropped,
            }
        }
    }

    impl ReplyProvider for CancelAwareStreamingProvider {
        fn metadata(&self) -> &ProviderMetadata {
            &self.metadata
        }

        fn reply(&self, _request: ReplyRequest) -> ReplyFuture<'_> {
            Box::pin(std::future::pending())
        }

        fn stream_reply(&self, _request: ReplyRequest) -> llm::ReplyStream<'_> {
            let prefix = self.prefix.clone();
            let blocked = self.blocked.clone();
            let dropped = self.dropped.clone();
            Box::pin(async_stream::stream! {
                let _drop_counter = StreamDropCounter(dropped);
                yield Ok(ReplyStreamEvent::TextDelta(prefix));
                blocked.wait().await;
                std::future::pending::<()>().await;
            })
        }
    }

    impl ToolThenFinalProvider {
        fn new(requests: Arc<StdMutex<Vec<ReplyRequest>>>) -> Self {
            Self {
                metadata: ProviderMetadata {
                    provider_id: "test-tool-then-final-provider".into(),
                    model: Some("test-model".into()),
                    reply_kind: ReplyKind::Model,
                },
                requests,
            }
        }
    }

    impl ReplyProvider for ToolThenFinalProvider {
        fn metadata(&self) -> &ProviderMetadata {
            &self.metadata
        }

        fn reply(&self, request: ReplyRequest) -> ReplyFuture<'_> {
            let output = {
                let mut requests = self.requests.lock().unwrap();
                requests.push(request.clone());
                match requests.len() {
                    1 => ReplyOutput::ToolCall {
                        call: ReplyToolCall::new(
                            "provider-call-approved-1",
                            request
                                .tools
                                .iter()
                                .find(|tool| tool.name == "dev_marker_write")
                                .expect("the local Agent request must expose dev_marker_write")
                                .name
                                .clone(),
                            serde_json::json!({ "marker": "agent-api-approved" }),
                        ),
                    },
                    2 => ReplyOutput::Final {
                        content: "tool completed".into(),
                    },
                    call => panic!("unexpected Agent provider call {call}"),
                }
            };
            let provider = self.metadata.clone();
            Box::pin(async move {
                Ok(ReplyResponse {
                    output,
                    finish_reason: Some("stop".into()),
                    provider,
                })
            })
        }
    }

    impl TodoThenFinalProvider {
        fn new(requests: Arc<StdMutex<Vec<ReplyRequest>>>) -> Self {
            Self {
                metadata: ProviderMetadata {
                    provider_id: "test-todo-then-final-provider".into(),
                    model: Some("test-model".into()),
                    reply_kind: ReplyKind::Model,
                },
                requests,
            }
        }
    }

    impl SpawnListThenFinalProvider {
        fn new(requests: Arc<StdMutex<Vec<ReplyRequest>>>) -> Self {
            Self {
                metadata: ProviderMetadata {
                    provider_id: "test-spawn-list-then-final-provider".into(),
                    model: Some("test-model".into()),
                    reply_kind: ReplyKind::Model,
                },
                requests,
            }
        }
    }

    impl ReplyProvider for SpawnListThenFinalProvider {
        fn metadata(&self) -> &ProviderMetadata {
            &self.metadata
        }

        fn reply(&self, request: ReplyRequest) -> ReplyFuture<'_> {
            let output =
                {
                    let mut requests = self.requests.lock().unwrap();
                    requests.push(request.clone());
                    let child_prompt = request
                        .messages
                        .iter()
                        .rev()
                        .find(|message| message.role == ReplyRole::User)
                        .map(|message| message.content.as_str());
                    if matches!(
                        child_prompt,
                        Some("inspect child alpha" | "inspect child beta")
                    ) {
                        ReplyOutput::Final {
                            content: format!("completed {child_prompt:?}"),
                        }
                    } else {
                        let tool_results = request
                            .messages
                            .iter()
                            .filter(|message| message.role == ReplyRole::Tool)
                            .count();
                        match tool_results {
                            0 | 1 => {
                                let spawn = request
                                    .tools
                                    .iter()
                                    .find(|tool| tool.name == subagents::SPAWN_AGENT_TOOL_NAME)
                                    .expect("every parent Agent request must expose spawn_agent");
                                assert_eq!(
                                    spawn.parameters["properties"]["prompt"]["maxLength"],
                                    subagents::SPAWN_AGENT_PROMPT_MAX_BYTES
                                );
                                let suffix = if tool_results == 0 { "alpha" } else { "beta" };
                                ReplyOutput::ToolCall {
                                    call: ReplyToolCall::new(
                                        format!("provider-call-spawn-agent-{suffix}"),
                                        subagents::SPAWN_AGENT_TOOL_NAME,
                                        serde_json::json!({
                                            "description": format!("Child {suffix}"),
                                            "prompt": format!("inspect child {suffix}"),
                                        }),
                                    ),
                                }
                            }
                            2 => {
                                let tool = request
                                    .tools
                                    .iter()
                                    .find(|tool| tool.name == subagents::LIST_AGENTS_TOOL_NAME)
                                    .expect("every parent Agent request must expose list_agents");
                                assert_eq!(
                                    tool.parameters["properties"]["cursor"]["maxLength"],
                                    subagents::LIST_AGENTS_CURSOR_MAX_BYTES
                                );
                                ReplyOutput::ToolCall {
                                    call: ReplyToolCall::new(
                                        "provider-call-list-agents-1",
                                        subagents::LIST_AGENTS_TOOL_NAME,
                                        serde_json::json!({"limit": 1}),
                                    ),
                                }
                            }
                            3 => {
                                let result = request
                            .messages
                            .iter()
                            .rev()
                            .find(|message| message.role == ReplyRole::Tool)
                            .and_then(|message| {
                                serde_json::from_str::<serde_json::Value>(&message.content).ok()
                            })
                            .expect("the parent continuation must contain the first catalog page");
                                let cursor = result["next_cursor"]
                                    .as_str()
                                    .expect("the first one-item page must expose a cursor");
                                ReplyOutput::ToolCall {
                                    call: ReplyToolCall::new(
                                        "provider-call-list-agents-2",
                                        subagents::LIST_AGENTS_TOOL_NAME,
                                        serde_json::json!({"cursor": cursor, "limit": 1}),
                                    ),
                                }
                            }
                            4 => ReplyOutput::Final {
                                content: "durable child catalog inspected".into(),
                            },
                            count => panic!("unexpected parent tool-result count {count}"),
                        }
                    }
                };
            let provider = self.metadata.clone();
            Box::pin(async move {
                Ok(ReplyResponse {
                    output,
                    finish_reason: Some("stop".into()),
                    provider,
                })
            })
        }
    }

    impl ReplyProvider for TodoThenFinalProvider {
        fn metadata(&self) -> &ProviderMetadata {
            &self.metadata
        }

        fn reply(&self, request: ReplyRequest) -> ReplyFuture<'_> {
            let output = {
                let mut requests = self.requests.lock().unwrap();
                requests.push(request.clone());
                match requests.len() {
                    1 => {
                        let todo = request
                            .tools
                            .iter()
                            .find(|tool| tool.name == planning::TODO_WRITE_TOOL_NAME)
                            .expect("every Agent request must expose todo_write");
                        assert_eq!(
                            todo.parameters["properties"]["todos"]["maxItems"],
                            planning::TODO_MAX_ITEMS
                        );
                        ReplyOutput::ToolCall {
                            call: ReplyToolCall::new(
                                "provider-call-todo-1",
                                planning::TODO_WRITE_TOOL_NAME,
                                serde_json::json!({
                                    "expected_revision": 0,
                                    "todos": [
                                        {"content": "inspect durable state", "status": "completed"},
                                        {"content": "return the answer", "status": "in_progress"}
                                    ]
                                }),
                            ),
                        }
                    }
                    2 => ReplyOutput::Final {
                        content: "durable plan completed".into(),
                    },
                    call => panic!("unexpected todo provider call {call}"),
                }
            };
            let provider = self.metadata.clone();
            Box::pin(async move {
                Ok(ReplyResponse {
                    output,
                    finish_reason: Some("stop".into()),
                    provider,
                })
            })
        }
    }

    impl GoalReadCreateThenFinalProvider {
        fn new(requests: Arc<StdMutex<Vec<ReplyRequest>>>) -> Self {
            Self {
                metadata: ProviderMetadata {
                    provider_id: "test-goal-read-create-provider".into(),
                    model: Some("test-model".into()),
                    reply_kind: ReplyKind::Model,
                },
                requests,
            }
        }
    }

    impl ReplyProvider for GoalReadCreateThenFinalProvider {
        fn metadata(&self) -> &ProviderMetadata {
            &self.metadata
        }

        fn reply(&self, request: ReplyRequest) -> ReplyFuture<'_> {
            let output = {
                let mut requests = self.requests.lock().unwrap();
                requests.push(request.clone());
                match requests.len() {
                    1 => ReplyOutput::ToolCall {
                        call: ReplyToolCall::new(
                            "provider-call-goal-read",
                            goals::GET_GOAL_TOOL_NAME,
                            serde_json::json!({}),
                        ),
                    },
                    2 => ReplyOutput::ToolCall {
                        call: ReplyToolCall::new(
                            "provider-call-goal-create",
                            goals::CREATE_GOAL_TOOL_NAME,
                            serde_json::json!({
                                "objective": "Deliver the durable Goal core",
                                "max_rounds": 32
                            }),
                        ),
                    },
                    3 => ReplyOutput::Final {
                        content: "durable Goal created".into(),
                    },
                    4 => ReplyOutput::ToolCall {
                        call: ReplyToolCall::new(
                            "provider-call-goal-round-read",
                            goals::GET_GOAL_TOOL_NAME,
                            serde_json::json!({}),
                        ),
                    },
                    5 => {
                        let goal_result = request
                            .messages
                            .iter()
                            .rev()
                            .find(|message| message.role == ReplyRole::Tool)
                            .and_then(|message| {
                                serde_json::from_str::<serde_json::Value>(&message.content).ok()
                            })
                            .expect("the Goal round read must return the current Goal");
                        ReplyOutput::ToolCall {
                            call: ReplyToolCall::new(
                                "provider-call-goal-round-complete",
                                goals::UPDATE_GOAL_TOOL_NAME,
                                serde_json::json!({
                                    "goal_id": goal_result["goal"]["id"],
                                    "expected_revision": goal_result["goal"]["revision"],
                                    "action": "complete"
                                }),
                            ),
                        }
                    }
                    6 => ReplyOutput::Final {
                        content: "durable Goal completed in round one".into(),
                    },
                    call => panic!("unexpected Goal provider call {call}"),
                }
            };
            let provider = self.metadata.clone();
            Box::pin(async move {
                Ok(ReplyResponse {
                    output,
                    finish_reason: Some("stop".into()),
                    provider,
                })
            })
        }
    }

    impl GoalCreateThenRoundTerminalProvider {
        fn new(requests: Arc<StdMutex<Vec<ReplyRequest>>>, terminal: GoalRoundTerminal) -> Self {
            Self {
                metadata: ProviderMetadata {
                    provider_id: "test-goal-round-terminal-provider".into(),
                    model: Some("test-model".into()),
                    reply_kind: ReplyKind::Model,
                },
                requests,
                terminal,
            }
        }
    }

    impl ReplyProvider for GoalCreateThenRoundTerminalProvider {
        fn metadata(&self) -> &ProviderMetadata {
            &self.metadata
        }

        fn reply(&self, request: ReplyRequest) -> ReplyFuture<'_> {
            let call = {
                let mut requests = self.requests.lock().unwrap();
                requests.push(request);
                requests.len()
            };
            let provider = self.metadata.clone();
            let terminal = self.terminal;
            Box::pin(async move {
                let output = match call {
                    1 => ReplyOutput::ToolCall {
                        call: ReplyToolCall::new(
                            "provider-call-goal-terminal-create",
                            goals::CREATE_GOAL_TOOL_NAME,
                            serde_json::json!({
                                "objective": "Exercise one bounded Goal round",
                                "max_rounds": 1
                            }),
                        ),
                    },
                    2 => ReplyOutput::Final {
                        content: "The bounded Goal is armed.".into(),
                    },
                    3 => match terminal {
                        GoalRoundTerminal::FinalAtLimit => ReplyOutput::Final {
                            content: "The Goal remains active at its round limit.".into(),
                        },
                        GoalRoundTerminal::KnownProviderFailure => {
                            return Err(ProviderError::InvalidRequest(
                                "fixture Goal round rejection",
                            ));
                        }
                    },
                    unexpected => panic!("unexpected Goal terminal provider call {unexpected}"),
                };
                Ok(ReplyResponse {
                    output,
                    finish_reason: Some("stop".into()),
                    provider,
                })
            })
        }
    }

    impl TerminalOpenSendThenFinalProvider {
        fn new(requests: Arc<StdMutex<Vec<ReplyRequest>>>) -> Self {
            Self {
                metadata: ProviderMetadata {
                    provider_id: "test-terminal-open-send-provider".into(),
                    model: Some("test-model".into()),
                    reply_kind: ReplyKind::Model,
                },
                requests,
            }
        }
    }

    impl ReplyProvider for TerminalOpenSendThenFinalProvider {
        fn metadata(&self) -> &ProviderMetadata {
            &self.metadata
        }

        fn reply(&self, request: ReplyRequest) -> ReplyFuture<'_> {
            let output = {
                let mut requests = self.requests.lock().unwrap();
                requests.push(request.clone());
                match requests.len() {
                    1 => {
                        for tool_name in [
                            TEST_TERMINAL_OPEN_TOOL_NAME,
                            TEST_TERMINAL_SEND_TOOL_NAME,
                            TEST_TERMINAL_READ_TOOL_NAME,
                            TEST_TERMINAL_SIGNAL_TOOL_NAME,
                            TEST_TERMINAL_CLOSE_TOOL_NAME,
                            TEST_TERMINAL_LIST_TOOL_NAME,
                        ] {
                            assert!(
                                request.tools.iter().any(|tool| tool.name == tool_name),
                                "terminal-enabled manifest must expose {tool_name}"
                            );
                        }
                        ReplyOutput::ToolCall {
                            call: ReplyToolCall::new(
                                "provider-call-terminal-open-1",
                                TEST_TERMINAL_OPEN_TOOL_NAME,
                                serde_json::json!({
                                    "name": "zeus-core",
                                    "cwd": ".",
                                }),
                            ),
                        }
                    }
                    2 => ReplyOutput::ToolCall {
                        call: ReplyToolCall::new(
                            "provider-call-terminal-send-2",
                            TEST_TERMINAL_SEND_TOOL_NAME,
                            serde_json::json!({
                                "session_id": "pty-1",
                                "text": "echo zeus",
                                "submit": true,
                            }),
                        ),
                    },
                    3 => ReplyOutput::Final {
                        content: "isolated terminal command completed".into(),
                    },
                    call => panic!("unexpected terminal provider call {call}"),
                }
            };
            let provider = self.metadata.clone();
            Box::pin(async move {
                Ok(ReplyResponse {
                    output,
                    finish_reason: Some("stop".into()),
                    provider,
                })
            })
        }
    }

    impl WorkspaceSearchThenFinalProvider {
        fn new(requests: Arc<StdMutex<Vec<ReplyRequest>>>) -> Self {
            Self {
                metadata: ProviderMetadata {
                    provider_id: "test-workspace-search-provider".into(),
                    model: Some("test-model".into()),
                    reply_kind: ReplyKind::Model,
                },
                requests,
            }
        }
    }

    impl WorkspaceFindThenFinalProvider {
        fn new(requests: Arc<StdMutex<Vec<ReplyRequest>>>) -> Self {
            Self {
                metadata: ProviderMetadata {
                    provider_id: "test-workspace-find-provider".into(),
                    model: Some("test-model".into()),
                    reply_kind: ReplyKind::Model,
                },
                requests,
            }
        }
    }

    impl ReplyProvider for WorkspaceFindThenFinalProvider {
        fn metadata(&self) -> &ProviderMetadata {
            &self.metadata
        }

        fn reply(&self, request: ReplyRequest) -> ReplyFuture<'_> {
            let output = {
                let mut requests = self.requests.lock().unwrap();
                requests.push(request.clone());
                match requests.len() {
                    1 => {
                        assert!(
                            request
                                .tools
                                .iter()
                                .any(|tool| tool.name == TEST_WORKSPACE_FIND_PATHS_TOOL_NAME)
                        );
                        ReplyOutput::ToolCall {
                            call: ReplyToolCall::new(
                                "provider-call-workspace-find-1",
                                TEST_WORKSPACE_FIND_PATHS_TOOL_NAME,
                                serde_json::json!({
                                    "path": ".",
                                    "pattern": "**/*.rs",
                                }),
                            ),
                        }
                    }
                    2 => ReplyOutput::ToolCall {
                        call: ReplyToolCall::new(
                            "provider-call-workspace-find-lines-2",
                            TEST_WORKSPACE_READ_LINES_TOOL_NAME,
                            serde_json::json!({
                                "path": "src/lib.rs",
                                "start_line": 1,
                                "end_line": 1,
                            }),
                        ),
                    },
                    3 => ReplyOutput::Final {
                        content: "workspace path discovery completed".into(),
                    },
                    call => panic!("unexpected workspace path discovery provider call {call}"),
                }
            };
            let provider = self.metadata.clone();
            Box::pin(async move {
                Ok(ReplyResponse {
                    output,
                    finish_reason: Some("stop".into()),
                    provider,
                })
            })
        }
    }

    impl ReplyProvider for WorkspaceSearchThenFinalProvider {
        fn metadata(&self) -> &ProviderMetadata {
            &self.metadata
        }

        fn reply(&self, request: ReplyRequest) -> ReplyFuture<'_> {
            let output = {
                let mut requests = self.requests.lock().unwrap();
                requests.push(request.clone());
                match requests.len() {
                    1 => {
                        assert!(
                            request
                                .tools
                                .iter()
                                .any(|tool| tool.name == TEST_WORKSPACE_READ_FILE_TOOL_NAME)
                        );
                        assert!(
                            request
                                .tools
                                .iter()
                                .any(|tool| tool.name == TEST_WORKSPACE_READ_LINES_TOOL_NAME)
                        );
                        assert!(
                            request
                                .tools
                                .iter()
                                .any(|tool| tool.name == TEST_WORKSPACE_LIST_DIRECTORY_TOOL_NAME)
                        );
                        assert!(
                            request
                                .tools
                                .iter()
                                .any(|tool| tool.name == TEST_WORKSPACE_SEARCH_TEXT_TOOL_NAME)
                        );
                        ReplyOutput::ToolCall {
                            call: ReplyToolCall::new(
                                "provider-call-workspace-search-1",
                                TEST_WORKSPACE_SEARCH_TEXT_TOOL_NAME,
                                serde_json::json!({
                                    "path": ".",
                                    "query": "governed_workspace",
                                }),
                            ),
                        }
                    }
                    2 => ReplyOutput::ToolCall {
                        call: ReplyToolCall::new(
                            "provider-call-workspace-lines-2",
                            TEST_WORKSPACE_READ_LINES_TOOL_NAME,
                            serde_json::json!({
                                "path": "src/lib.rs",
                                "start_line": 1,
                                "end_line": 1,
                            }),
                        ),
                    },
                    3 => ReplyOutput::Final {
                        content: "workspace read completed".into(),
                    },
                    call => panic!("unexpected workspace Agent provider call {call}"),
                }
            };
            let provider = self.metadata.clone();
            Box::pin(async move {
                Ok(ReplyResponse {
                    output,
                    finish_reason: Some("stop".into()),
                    provider,
                })
            })
        }
    }

    impl WorkspaceReplaceThenFinalProvider {
        fn new(requests: Arc<StdMutex<Vec<ReplyRequest>>>) -> Self {
            Self {
                metadata: ProviderMetadata {
                    provider_id: "test-workspace-replace-provider".into(),
                    model: Some("test-model".into()),
                    reply_kind: ReplyKind::Model,
                },
                requests,
            }
        }
    }

    impl ReplyProvider for WorkspaceReplaceThenFinalProvider {
        fn metadata(&self) -> &ProviderMetadata {
            &self.metadata
        }

        fn reply(&self, request: ReplyRequest) -> ReplyFuture<'_> {
            let output = {
                let mut requests = self.requests.lock().unwrap();
                requests.push(request.clone());
                match requests.len() {
                    1 => {
                        assert!(
                            request
                                .tools
                                .iter()
                                .any(|tool| tool.name == TEST_WORKSPACE_REPLACE_TEXT_TOOL_NAME)
                        );
                        ReplyOutput::ToolCall {
                            call: ReplyToolCall::new(
                                "provider-call-workspace-replace-1",
                                TEST_WORKSPACE_REPLACE_TEXT_TOOL_NAME,
                                serde_json::json!({
                                    "path": "src/lib.rs",
                                    "old_text": "before",
                                    "new_text": "after",
                                }),
                            ),
                        }
                    }
                    2 => ReplyOutput::Final {
                        content: "workspace edit completed".into(),
                    },
                    call => panic!("unexpected workspace edit provider call {call}"),
                }
            };
            let provider = self.metadata.clone();
            Box::pin(async move {
                Ok(ReplyResponse {
                    output,
                    finish_reason: Some("stop".into()),
                    provider,
                })
            })
        }
    }

    impl WorkspaceCreateThenFinalProvider {
        fn new(requests: Arc<StdMutex<Vec<ReplyRequest>>>) -> Self {
            Self {
                metadata: ProviderMetadata {
                    provider_id: "test-workspace-create-provider".into(),
                    model: Some("test-model".into()),
                    reply_kind: ReplyKind::Model,
                },
                requests,
            }
        }
    }

    impl ReplyProvider for WorkspaceCreateThenFinalProvider {
        fn metadata(&self) -> &ProviderMetadata {
            &self.metadata
        }

        fn reply(&self, request: ReplyRequest) -> ReplyFuture<'_> {
            let output = {
                let mut requests = self.requests.lock().unwrap();
                requests.push(request.clone());
                match requests.len() {
                    1 => {
                        assert!(
                            request
                                .tools
                                .iter()
                                .any(|tool| tool.name == TEST_WORKSPACE_CREATE_FILE_TOOL_NAME)
                        );
                        ReplyOutput::ToolCall {
                            call: ReplyToolCall::new(
                                "provider-call-workspace-create-1",
                                TEST_WORKSPACE_CREATE_FILE_TOOL_NAME,
                                serde_json::json!({
                                    "path": "src/generated.rs",
                                    "content": "pub fn generated() {}\n",
                                }),
                            ),
                        }
                    }
                    2 => ReplyOutput::Final {
                        content: "workspace file created".into(),
                    },
                    call => panic!("unexpected workspace create provider call {call}"),
                }
            };
            let provider = self.metadata.clone();
            Box::pin(async move {
                Ok(ReplyResponse {
                    output,
                    finish_reason: Some("stop".into()),
                    provider,
                })
            })
        }
    }

    impl WorkspaceInsertThenFinalProvider {
        fn new(requests: Arc<StdMutex<Vec<ReplyRequest>>>) -> Self {
            Self {
                metadata: ProviderMetadata {
                    provider_id: "test-workspace-insert-provider".into(),
                    model: Some("test-model".into()),
                    reply_kind: ReplyKind::Model,
                },
                requests,
            }
        }
    }

    impl ReplyProvider for WorkspaceInsertThenFinalProvider {
        fn metadata(&self) -> &ProviderMetadata {
            &self.metadata
        }

        fn reply(&self, request: ReplyRequest) -> ReplyFuture<'_> {
            let output = {
                let mut requests = self.requests.lock().unwrap();
                requests.push(request.clone());
                match requests.len() {
                    1 => {
                        assert!(
                            request
                                .tools
                                .iter()
                                .any(|tool| tool.name == TEST_WORKSPACE_INSERT_TEXT_TOOL_NAME)
                        );
                        ReplyOutput::ToolCall {
                            call: ReplyToolCall::new(
                                "provider-call-workspace-insert-1",
                                TEST_WORKSPACE_INSERT_TEXT_TOOL_NAME,
                                serde_json::json!({
                                    "path": "src/lib.rs",
                                    "after_line": 1,
                                    "text": "between",
                                }),
                            ),
                        }
                    }
                    2 => ReplyOutput::Final {
                        content: "workspace text inserted".into(),
                    },
                    call => panic!("unexpected workspace insert provider call {call}"),
                }
            };
            let provider = self.metadata.clone();
            Box::pin(async move {
                Ok(ReplyResponse {
                    output,
                    finish_reason: Some("stop".into()),
                    provider,
                })
            })
        }
    }

    impl HistoryThenToolProvider {
        fn new(requests: Arc<StdMutex<Vec<ReplyRequest>>>) -> Self {
            Self {
                metadata: ProviderMetadata {
                    provider_id: "test-history-then-tool-provider".into(),
                    model: Some("test-model".into()),
                    reply_kind: ReplyKind::Model,
                },
                requests,
            }
        }
    }

    impl ReplyProvider for HistoryThenToolProvider {
        fn metadata(&self) -> &ProviderMetadata {
            &self.metadata
        }

        fn reply(&self, request: ReplyRequest) -> ReplyFuture<'_> {
            let output = {
                let mut requests = self.requests.lock().unwrap();
                requests.push(request.clone());
                match requests.len() {
                    1 | 2 => ReplyOutput::Final {
                        content: "a".repeat(40_000),
                    },
                    3 => ReplyOutput::ToolCall {
                        call: ReplyToolCall::new(
                            "provider-call-history",
                            request
                                .tools
                                .iter()
                                .find(|tool| tool.name == "dev_marker_write")
                                .expect("the local Agent request must expose dev_marker_write")
                                .name
                                .clone(),
                            serde_json::json!({ "marker": "history-trimmed" }),
                        ),
                    },
                    4 => ReplyOutput::Final {
                        content: "trimmed history tool completed".into(),
                    },
                    call => panic!("unexpected Agent provider call {call}"),
                }
            };
            let provider = self.metadata.clone();
            Box::pin(async move {
                Ok(ReplyResponse {
                    output,
                    finish_reason: Some("stop".into()),
                    provider,
                })
            })
        }
    }

    struct OversizedReplyProvider {
        metadata: ProviderMetadata,
        calls: Arc<AtomicUsize>,
    }

    impl OversizedReplyProvider {
        fn new(calls: Arc<AtomicUsize>) -> Self {
            Self {
                metadata: ProviderMetadata {
                    provider_id: "test-oversized-provider".into(),
                    model: Some("test-model".into()),
                    reply_kind: ReplyKind::Model,
                },
                calls,
            }
        }
    }

    impl ReplyProvider for OversizedReplyProvider {
        fn metadata(&self) -> &ProviderMetadata {
            &self.metadata
        }

        fn reply(&self, _request: ReplyRequest) -> ReplyFuture<'_> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            let provider = self.metadata.clone();
            Box::pin(async move {
                Ok(ReplyResponse {
                    output: ReplyOutput::Final {
                        content: "x".repeat(protocol::ASSISTANT_MESSAGE_MAX_BYTES + 1),
                    },
                    finish_reason: Some("stop".into()),
                    provider,
                })
            })
        }
    }

    impl CountingProvider {
        fn new(calls: Arc<AtomicUsize>) -> Self {
            Self {
                metadata: ProviderMetadata {
                    provider_id: "test-counting-provider".into(),
                    model: Some("test-model".into()),
                    reply_kind: ReplyKind::Model,
                },
                calls,
            }
        }
    }

    impl ReplyProvider for CountingProvider {
        fn metadata(&self) -> &ProviderMetadata {
            &self.metadata
        }

        fn reply(&self, _request: ReplyRequest) -> ReplyFuture<'_> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            Box::pin(async {
                Err(ProviderError::InvalidRequest(
                    "the counting provider must not be called",
                ))
            })
        }
    }

    #[tokio::test]
    async fn agent_output_endpoints_replay_durable_stream_chunks() {
        let store = DemoStore::seeded().await.unwrap();
        let owner = provision_test_owner(&store, "user-output", "output-owner").await;
        let session_id = "session-agent-output";
        let turn_id = "turn-agent-output";
        store
            .create_session_for_actor(
                &owner.authz,
                CreateSessionRequest {
                    id: session_id.into(),
                    title: "Durable Agent output".into(),
                },
                "create-agent-output",
            )
            .await
            .unwrap();
        let first_delta = "a".repeat(AGENT_OUTPUT_FLUSH_TARGET_BYTES);
        let second_delta = " durable tail".to_owned();
        let app = authenticated_app_with_provider(
            store.clone(),
            false,
            Arc::new(StreamingProvider::new(
                first_delta.clone(),
                second_delta.clone(),
            )),
        )
        .unwrap();

        let response = app
            .clone()
            .oneshot(
                Request::post(format!("/api/v1/sessions/{session_id}/turns"))
                    .header(header::HOST, "zeus.test")
                    .header(header::ORIGIN, "http://zeus.test")
                    .header(header::COOKIE, &owner.cookie_header)
                    .header(CSRF_HEADER, &owner.csrf_token)
                    .header(header::CONTENT_TYPE, "application/json")
                    .header("idempotency-key", "start-agent-output")
                    .body(Body::from(
                        serde_json::json!({
                            "turn_id": turn_id,
                            "user_message": "stream a durable response",
                            "expected_sequence": 1,
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::ACCEPTED);
        let ready = wait_for_ready_session(&store, &owner.authz, session_id).await;
        assert_eq!(
            ready.turns[0].assistant_message.as_deref(),
            Some(format!("{first_delta}{second_delta}").as_str())
        );

        let output = app
            .clone()
            .oneshot(
                Request::get(format!(
                    "/api/v1/sessions/{session_id}/turns/{turn_id}/output?after=0&limit=1"
                ))
                .header(header::HOST, "zeus.test")
                .header(header::COOKIE, &owner.cookie_header)
                .body(Body::empty())
                .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(output.status(), StatusCode::OK);
        assert_eq!(
            output.headers().get(header::CACHE_CONTROL),
            Some(&HeaderValue::from_static("no-store"))
        );
        let first_page: protocol::AgentOutputChunkPage = response_json(output).await;
        assert_eq!(first_page.items.len(), 1);
        assert_eq!(first_page.items[0].content, first_delta);
        assert_eq!(first_page.next_after, Some(1));
        assert_eq!(first_page.head_sequence, 2);
        assert!(first_page.has_more);
        assert!(first_page.terminal);

        let events = app
            .oneshot(
                Request::get(format!(
                    "/api/v1/sessions/{session_id}/turns/{turn_id}/output/events?after=0"
                ))
                .header(header::HOST, "zeus.test")
                .header(header::COOKIE, &owner.cookie_header)
                .body(Body::empty())
                .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(events.status(), StatusCode::OK);
        assert_eq!(
            events.headers().get(header::CACHE_CONTROL),
            Some(&HeaderValue::from_static("no-store"))
        );
        let event_body = String::from_utf8(
            events
                .into_body()
                .collect()
                .await
                .unwrap()
                .to_bytes()
                .to_vec(),
        )
        .unwrap();
        assert_eq!(event_body.matches("event: agent.output").count(), 2);
        assert!(event_body.contains("id: 1"));
        assert!(event_body.contains("id: 2"));
        assert!(event_body.contains(&second_delta));
    }

    #[tokio::test]
    async fn truncated_agent_stream_persists_its_received_prefix_before_settlement() {
        let store = DemoStore::seeded().await.unwrap();
        let owner = provision_test_owner(&store, "user-truncated-output", "truncated-owner").await;
        let session_id = "session-truncated-output";
        let turn_id = "turn-truncated-output";
        store
            .create_session_for_actor(
                &owner.authz,
                CreateSessionRequest {
                    id: session_id.into(),
                    title: "Truncated Agent output".into(),
                },
                "create-truncated-output",
            )
            .await
            .unwrap();
        let received_prefix = "provider prefix before transport failure".to_owned();
        let app = authenticated_app_with_provider(
            store.clone(),
            false,
            Arc::new(TruncatedStreamingProvider::new(received_prefix.clone())),
        )
        .unwrap();

        let response = app
            .oneshot(
                Request::post(format!("/api/v1/sessions/{session_id}/turns"))
                    .header(header::HOST, "zeus.test")
                    .header(header::ORIGIN, "http://zeus.test")
                    .header(header::COOKIE, &owner.cookie_header)
                    .header(CSRF_HEADER, &owner.csrf_token)
                    .header(header::CONTENT_TYPE, "application/json")
                    .header("idempotency-key", "start-truncated-output")
                    .body(Body::from(
                        serde_json::json!({
                            "turn_id": turn_id,
                            "user_message": "preserve the received prefix",
                            "expected_sequence": 1,
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::ACCEPTED);
        let agent = wait_for_agent_status(
            &store,
            &owner.authz,
            session_id,
            turn_id,
            protocol::AgentTurnStatus::NeedsAttention,
        )
        .await;
        assert_eq!(
            agent
                .last_error
                .as_ref()
                .and_then(|error| error.get("code"))
                .and_then(serde_json::Value::as_str),
            Some("provider_transport_failed")
        );
        let output = store
            .agent_output_chunk_page_for_actor(&owner.authz, session_id, turn_id, 0, 10)
            .await
            .unwrap();
        assert_eq!(output.items.len(), 1);
        assert_eq!(output.items[0].content, received_prefix);
        assert!(output.terminal);
    }

    #[tokio::test]
    async fn running_model_cancel_drops_provider_stream_and_keeps_durable_prefix() {
        let store = DemoStore::seeded().await.unwrap();
        let owner =
            provision_test_owner(&store, "user-running-cancel", "running-cancel-owner").await;
        let session_id = "session-running-model-cancel";
        let turn_id = "turn-running-model-cancel";
        store
            .create_session_for_actor(
                &owner.authz,
                CreateSessionRequest {
                    id: session_id.into(),
                    title: "Running model cancellation".into(),
                },
                "create-running-model-cancel",
            )
            .await
            .unwrap();
        let prefix = "p".repeat(AGENT_OUTPUT_FLUSH_TARGET_BYTES);
        let blocked = Arc::new(tokio::sync::Barrier::new(2));
        let dropped = Arc::new(AtomicUsize::new(0));
        let app = authenticated_app_with_provider(
            store.clone(),
            false,
            Arc::new(CancelAwareStreamingProvider::new(
                prefix.clone(),
                blocked.clone(),
                dropped.clone(),
            )),
        )
        .unwrap();

        let started = app
            .clone()
            .oneshot(
                Request::post(format!("/api/v1/sessions/{session_id}/turns"))
                    .header(header::HOST, "zeus.test")
                    .header(header::ORIGIN, "http://zeus.test")
                    .header(header::COOKIE, &owner.cookie_header)
                    .header(CSRF_HEADER, &owner.csrf_token)
                    .header(header::CONTENT_TYPE, "application/json")
                    .header("idempotency-key", "start-running-model-cancel")
                    .body(Body::from(
                        serde_json::json!({
                            "turn_id": turn_id,
                            "user_message": "stop after the durable prefix",
                            "expected_sequence": 1,
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(started.status(), StatusCode::ACCEPTED);
        tokio::time::timeout(Duration::from_secs(2), blocked.wait())
            .await
            .expect("provider stream must reach its cancellable wait point");
        let detail = store
            .agent_turn_detail_for_actor(&owner.authz, session_id, turn_id)
            .await
            .unwrap();
        assert_eq!(detail.status, protocol::AgentTurnStatus::ModelRunning);

        let cancelled = app
            .oneshot(
                Request::put(format!(
                    "/api/v1/sessions/{session_id}/turns/{turn_id}/agent/cancel"
                ))
                .header(header::HOST, "zeus.test")
                .header(header::ORIGIN, "http://zeus.test")
                .header(header::COOKIE, &owner.cookie_header)
                .header(CSRF_HEADER, &owner.csrf_token)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::json!({"expected_revision": detail.revision}).to_string(),
                ))
                .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(cancelled.status(), StatusCode::OK);
        let cancelled: CancelAgentTurnResponse = response_json(cancelled).await;
        assert_eq!(cancelled.agent.status, protocol::AgentTurnStatus::Failed);

        tokio::time::timeout(Duration::from_secs(2), async {
            while dropped.load(Ordering::Acquire) == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("cancellation must drop the active provider stream");
        let output = store
            .agent_output_chunk_page_for_actor(&owner.authz, session_id, turn_id, 0, 10)
            .await
            .unwrap();
        assert_eq!(output.items.len(), 1);
        assert_eq!(output.items[0].content, prefix);
        assert!(output.terminal);
        store.readiness().await.unwrap();
    }

    #[tokio::test]
    async fn durable_followup_endpoint_drives_the_next_agent_turn() {
        let store = DemoStore::seeded().await.unwrap();
        let owner = provision_test_owner(&store, "user-followup", "followup-owner").await;
        let session_id = "session-durable-followup";
        store
            .create_session_for_actor(
                &owner.authz,
                CreateSessionRequest {
                    id: session_id.into(),
                    title: "Durable follow-up".into(),
                },
                "create-durable-followup",
            )
            .await
            .unwrap();
        let requests = Arc::new(StdMutex::new(Vec::new()));
        let app = authenticated_app_with_provider(
            store.clone(),
            false,
            Arc::new(RecordingProvider::new(Arc::clone(&requests))),
        )
        .unwrap();
        let response = app
            .clone()
            .oneshot(
                Request::post(format!("/api/v1/sessions/{session_id}/followups"))
                    .header(header::HOST, "zeus.test")
                    .header(header::ORIGIN, "http://zeus.test")
                    .header(header::COOKIE, &owner.cookie_header)
                    .header(CSRF_HEADER, &owner.csrf_token)
                    .header(header::CONTENT_TYPE, "application/json")
                    .header("idempotency-key", "enqueue-durable-followup")
                    .body(Body::from(
                        serde_json::json!({
                            "turn_id": "turn-durable-followup",
                            "user_message": "Continue this Session from the durable inbox",
                            "expected_sequence": 1,
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::ACCEPTED);
        let admitted = response_json::<EnqueueSessionFollowupResponse>(response).await;
        assert_eq!(
            admitted.followup.status,
            protocol::SessionFollowupStatus::Queued
        );

        let ready = wait_for_session_state_and_turns(
            &store,
            &owner.authz,
            session_id,
            SessionStatus::Ready,
            1,
        )
        .await;
        assert_eq!(ready.turns[0].id, "turn-durable-followup");
        assert_eq!(
            ready.turns[0].assistant_message.as_deref(),
            Some("durable answer 1")
        );
        assert_eq!(requests.lock().unwrap().len(), 1);

        let response = app
            .oneshot(
                Request::get(format!("/api/v1/sessions/{session_id}/followups"))
                    .header(header::HOST, "zeus.test")
                    .header(header::COOKIE, &owner.cookie_header)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let list = response_json::<SessionFollowupListResponse>(response).await;
        assert_eq!(list.items.len(), 1);
        assert_eq!(
            list.items[0].status,
            protocol::SessionFollowupStatus::Claimed
        );
    }

    #[tokio::test]
    async fn long_agent_session_compacts_oldest_prefix_and_injects_checkpoint() {
        let store = DemoStore::seeded().await.unwrap();
        let owner = provision_test_owner(&store, "user-compaction", "compaction-owner").await;
        let session_id = "session-agent-compaction";
        store
            .create_session_for_actor(
                &owner.authz,
                CreateSessionRequest {
                    id: session_id.into(),
                    title: "Durable context compaction".into(),
                },
                "create-agent-compaction",
            )
            .await
            .unwrap();
        let requests = Arc::new(StdMutex::new(Vec::new()));
        let app = authenticated_app_with_provider(
            store.clone(),
            false,
            Arc::new(RecordingProvider::new(Arc::clone(&requests))),
        )
        .unwrap();
        let mut expected_sequence = 1_u64;

        for ordinal in 0..27_u64 {
            let response = app
                .clone()
                .oneshot(
                    Request::post(format!("/api/v1/sessions/{session_id}/turns"))
                        .header(header::HOST, "zeus.test")
                        .header(header::ORIGIN, "http://zeus.test")
                        .header(header::COOKIE, &owner.cookie_header)
                        .header(CSRF_HEADER, &owner.csrf_token)
                        .header(header::CONTENT_TYPE, "application/json")
                        .header("idempotency-key", format!("compaction-turn-{ordinal}"))
                        .body(Body::from(
                            serde_json::json!({
                                "turn_id": format!("turn-agent-compaction-{ordinal}"),
                                "user_message": format!("remember durable fact {ordinal}"),
                                "expected_sequence": expected_sequence,
                            })
                            .to_string(),
                        ))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::ACCEPTED);
            let ready = wait_for_ready_session(&store, &owner.authz, session_id).await;
            expected_sequence = ready.session.sequence;
        }

        let checkpoint = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if let Some(checkpoint) = store
                    .session_context_checkpoint_for_actor(
                        &owner.authz,
                        session_id,
                        expected_sequence,
                    )
                    .await
                    .unwrap()
                {
                    break checkpoint;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("the compaction worker must persist its checkpoint");
        assert_eq!(checkpoint.generation, 1);
        assert_eq!(checkpoint.source_end_sequence, 40);
        assert_eq!(checkpoint.summary_text, "durable answer 28");

        let response = app
            .clone()
            .oneshot(
                Request::post(format!("/api/v1/sessions/{session_id}/turns"))
                    .header(header::HOST, "zeus.test")
                    .header(header::ORIGIN, "http://zeus.test")
                    .header(header::COOKIE, &owner.cookie_header)
                    .header(CSRF_HEADER, &owner.csrf_token)
                    .header(header::CONTENT_TYPE, "application/json")
                    .header("idempotency-key", "compaction-turn-after-checkpoint")
                    .body(Body::from(
                        serde_json::json!({
                            "turn_id": "turn-agent-after-compaction",
                            "user_message": "continue from the compacted facts",
                            "expected_sequence": expected_sequence,
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        if response.status() != StatusCode::ACCEPTED {
            let status = response.status();
            let body = response_json::<serde_json::Value>(response).await;
            panic!("post-compaction turn returned {status}: {body}");
        }
        let ready = wait_for_ready_session(&store, &owner.authz, session_id).await;
        assert_eq!(ready.turns.len(), 28);

        let recorded = requests.lock().unwrap();
        assert_eq!(recorded.len(), 29);
        assert_eq!(recorded[27].messages[0].role, ReplyRole::System);
        assert!(recorded[27].tools.is_empty());
        let next_agent = &recorded[28];
        assert_eq!(next_agent.messages[0].role, ReplyRole::System);
        assert_eq!(next_agent.messages[1].role, ReplyRole::Checkpoint);
        assert_eq!(
            next_agent.messages[1].content,
            "<compacted-summary>\ndurable answer 28\n</compacted-summary>"
        );
        assert_eq!(next_agent.messages[2].content, "remember durable fact 13");
        assert!(
            next_agent
                .messages
                .iter()
                .all(|message| message.content != "remember durable fact 0")
        );
    }

    #[tokio::test]
    async fn agent_initial_content_budget_rejects_before_durable_writes() {
        let store = DemoStore::seeded().await.unwrap();
        let owner = provision_test_owner(&store, "user-agent-budget", "agent-budget-owner").await;
        let session_id = "session-agent-budget";
        store
            .create_session_for_actor(
                &owner.authz,
                CreateSessionRequest {
                    id: session_id.into(),
                    title: "Agent initial content budget".into(),
                },
                "create-agent-budget",
            )
            .await
            .unwrap();

        let requests = Arc::new(StdMutex::new(Vec::new()));
        let app = authenticated_app_with_provider(
            store.clone(),
            false,
            Arc::new(RecordingProvider::new(Arc::clone(&requests))),
        )
        .unwrap();
        let context = store
            .session_agent_knowledge_context(&owner.authz, "budget probe")
            .await
            .unwrap()
            .snapshot
            .snapshot()
            .canonical_context()
            .to_owned();
        let user_message_budget = AGENT_REQUEST_INITIAL_CONTENT_MAX_BYTES
            .checked_sub(store.session_agent_system_prompt().len())
            .and_then(|remaining| remaining.checked_sub(context.len()))
            .unwrap();
        assert!(user_message_budget < protocol::USER_MESSAGE_MAX_BYTES);

        let send_turn =
            |turn_id: &str, user_message: String, expected_sequence: u64, idempotency_key: &str| {
                Request::post(format!("/api/v1/sessions/{session_id}/turns"))
                    .header(header::HOST, "zeus.test")
                    .header(header::ORIGIN, "http://zeus.test")
                    .header(header::COOKIE, &owner.cookie_header)
                    .header(CSRF_HEADER, &owner.csrf_token)
                    .header(header::CONTENT_TYPE, "application/json")
                    .header("idempotency-key", idempotency_key)
                    .body(Body::from(
                        serde_json::json!({
                            "turn_id": turn_id,
                            "user_message": user_message,
                            "expected_sequence": expected_sequence,
                        })
                        .to_string(),
                    ))
                    .unwrap()
            };

        let accepted = app
            .clone()
            .oneshot(send_turn(
                "turn-agent-budget-exact",
                "x".repeat(user_message_budget),
                1,
                "agent-budget-exact",
            ))
            .await
            .unwrap();
        assert_eq!(accepted.status(), StatusCode::ACCEPTED);
        let after_accepted = wait_for_ready_session(&store, &owner.authz, session_id).await;
        {
            let recorded = requests.lock().unwrap();
            assert_eq!(recorded.len(), 1);
            assert_eq!(recorded[0].messages[0].role, ReplyRole::System);
            assert_eq!(recorded[0].messages[1].role, ReplyRole::User);
            assert_eq!(recorded[0].messages[2].role, ReplyRole::Context);
            assert_eq!(recorded[0].messages[2].content, context);
            assert_eq!(recorded[0].messages[1].content.len(), user_message_budget);
            assert_eq!(
                recorded[0]
                    .messages
                    .iter()
                    .map(|message| message.content.len())
                    .sum::<usize>(),
                AGENT_REQUEST_INITIAL_CONTENT_MAX_BYTES
            );
        }

        let sequence_before_rejection = after_accepted.session.sequence;
        let turns_before_rejection = after_accepted.turns.len();
        let rejected = app
            .clone()
            .oneshot(send_turn(
                "turn-agent-budget-too-large",
                "x".repeat(user_message_budget + 1),
                sequence_before_rejection,
                "agent-budget-too-large",
            ))
            .await
            .unwrap();
        assert_eq!(rejected.status(), StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(
            rejected.headers().get(header::CACHE_CONTROL),
            Some(&HeaderValue::from_static("no-store"))
        );
        let problem: ProblemDetails = response_json(rejected).await;
        assert_eq!(problem.code, "agent_request_too_large");

        let unchanged = store
            .get_session_for_actor(
                &owner.authz,
                session_id,
                None,
                protocol::COLLECTION_PAGE_DEFAULT_LIMIT,
                None,
                protocol::COLLECTION_PAGE_DEFAULT_LIMIT,
                None,
                protocol::EVENT_PAGE_DEFAULT_LIMIT,
            )
            .await
            .unwrap();
        assert_eq!(unchanged.session.sequence, sequence_before_rejection);
        assert_eq!(unchanged.turns.len(), turns_before_rejection);
        assert!(
            unchanged
                .turns
                .iter()
                .all(|turn| turn.id != "turn-agent-budget-too-large")
        );
        assert_eq!(requests.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn durable_reply_context_is_multi_turn_and_stable_on_late_replay() {
        let unique = UserId::generate().unwrap();
        let path = std::env::temp_dir().join(format!(
            "zeus-api-reply-context-{}.db",
            unique.as_str().replace(':', "-")
        ));
        let store = DemoStore::open(&path).await.unwrap();
        let owner = provision_test_owner(&store, "user-context", "context-owner").await;
        store
            .create_session_for_actor(
                &owner.authz,
                CreateSessionRequest {
                    id: "session-reply-context".into(),
                    title: "Durable reply context".into(),
                },
                "create-reply-context",
            )
            .await
            .unwrap();
        let requests = Arc::new(StdMutex::new(Vec::new()));
        let app = authenticated_app_with_provider(
            store.clone(),
            false,
            Arc::new(RecordingProvider::new(Arc::clone(&requests))),
        )
        .unwrap();

        let send_turn =
            |turn_id: &str, user_message: &str, expected_sequence: u64, idempotency_key: &str| {
                Request::post("/api/v1/sessions/session-reply-context/turns")
                    .header(header::HOST, "zeus.test")
                    .header(header::ORIGIN, "http://zeus.test")
                    .header(header::COOKIE, &owner.cookie_header)
                    .header(CSRF_HEADER, &owner.csrf_token)
                    .header(header::CONTENT_TYPE, "application/json")
                    .header("idempotency-key", idempotency_key)
                    .body(Body::from(
                        serde_json::json!({
                            "turn_id": turn_id,
                            "user_message": user_message,
                            "expected_sequence": expected_sequence,
                        })
                        .to_string(),
                    ))
                    .unwrap()
            };

        let first = app
            .clone()
            .oneshot(send_turn(
                "turn-context-1",
                "remember alpha",
                1,
                "context-1",
            ))
            .await
            .unwrap();
        assert_eq!(first.status(), StatusCode::ACCEPTED);
        let after_first =
            wait_for_ready_session(&store, &owner.authz, "session-reply-context").await;
        assert_eq!(after_first.session.sequence, 4);

        let second = app
            .clone()
            .oneshot(send_turn(
                "turn-context-2",
                "what did I say?",
                after_first.session.sequence,
                "context-2",
            ))
            .await
            .unwrap();
        assert_eq!(second.status(), StatusCode::ACCEPTED);
        let after_second =
            wait_for_ready_session(&store, &owner.authz, "session-reply-context").await;
        assert_eq!(after_second.session.sequence, 7);

        let replay = app
            .clone()
            .oneshot(send_turn(
                "turn-context-2",
                "what did I say?",
                after_first.session.sequence,
                "context-2",
            ))
            .await
            .unwrap();
        assert_eq!(replay.status(), StatusCode::ACCEPTED);
        let replay: StartTurnResponse = response_json(replay).await;
        assert!(replay.replayed);
        let agent = app
            .clone()
            .oneshot(
                Request::get("/api/v1/sessions/session-reply-context/turns/turn-context-2/agent")
                    .header(header::HOST, "zeus.test")
                    .header(header::COOKIE, &owner.cookie_header)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(agent.status(), StatusCode::OK);
        let agent: AgentTurnDetail = response_json(agent).await;
        assert_eq!(agent.status, protocol::AgentTurnStatus::Succeeded);
        assert_eq!(agent.model_steps, 1);
        assert!(agent.calls.is_empty());
        let manifest_digest = agent
            .deployment_manifest_digest
            .clone()
            .expect("new Agent turns must expose their deployment binding");

        let explanation = app
            .clone()
            .oneshot(
                Request::get(
                    "/api/v1/sessions/session-reply-context/turns/turn-context-2/agent/explain",
                )
                .header(header::HOST, "zeus.test")
                .header(header::COOKIE, &owner.cookie_header)
                .body(Body::empty())
                .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(explanation.status(), StatusCode::OK);
        assert_eq!(
            explanation.headers().get(header::CACHE_CONTROL),
            Some(&HeaderValue::from_static("no-store"))
        );
        let explanation: AgentDeploymentExplainResponse = response_json(explanation).await;
        assert!(!explanation.legacy_unbound);
        assert!(explanation.matches_current);
        assert!(explanation.diff.is_none());
        assert_eq!(explanation.current_manifest.digest, manifest_digest);
        assert_eq!(
            explanation
                .persisted_manifest
                .as_ref()
                .map(|manifest| manifest.digest.as_str()),
            Some(manifest_digest.as_str())
        );
        let explanation_json = serde_json::to_string(&explanation).unwrap();
        for forbidden in ["endpoint", "api_key", "secret_value"] {
            assert!(
                !explanation_json.contains(forbidden),
                "deployment explanation exposed forbidden field {forbidden}"
            );
        }

        let deployment_alias = app
            .clone()
            .oneshot(
                Request::get(
                    "/api/v1/sessions/session-reply-context/turns/turn-context-2/agent/deployment/explain",
                )
                .header(header::HOST, "zeus.test")
                .header(header::COOKIE, &owner.cookie_header)
                .body(Body::empty())
                .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(deployment_alias.status(), StatusCode::OK);
        assert_eq!(
            deployment_alias.headers().get(header::CACHE_CONTROL),
            Some(&HeaderValue::from_static("no-store"))
        );
        let deployment_alias: AgentDeploymentExplainResponse =
            response_json(deployment_alias).await;
        assert_eq!(deployment_alias.current_manifest.digest, manifest_digest);

        let execution = app
            .clone()
            .oneshot(
                Request::get(
                    "/api/v1/sessions/session-reply-context/turns/turn-context-2/agent/execution/explain",
                )
                .header(header::HOST, "zeus.test")
                .header(header::COOKIE, &owner.cookie_header)
                .body(Body::empty())
                .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(execution.status(), StatusCode::OK);
        assert_eq!(
            execution.headers().get(header::CACHE_CONTROL),
            Some(&HeaderValue::from_static("no-store"))
        );
        let execution: AgentExecutionExplain = response_json(execution).await;
        execution.validate().unwrap();
        assert_eq!(execution.agent.id, agent.id);
        assert_eq!(
            execution
                .manifest
                .as_ref()
                .map(|manifest| manifest.digest.as_str()),
            Some(manifest_digest.as_str())
        );
        assert_eq!(execution.epochs.len(), 1);
        assert!(!execution.facts.is_empty());

        let epoch = app
            .clone()
            .oneshot(
                Request::get(
                    "/api/v1/sessions/session-reply-context/turns/turn-context-2/agent/execution/epochs/1",
                )
                .header(header::HOST, "zeus.test")
                .header(header::COOKIE, &owner.cookie_header)
                .body(Body::empty())
                .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(epoch.status(), StatusCode::OK);
        assert_eq!(
            epoch.headers().get(header::CACHE_CONTROL),
            Some(&HeaderValue::from_static("no-store"))
        );
        let epoch: AgentRunEpochExplain = response_json(epoch).await;
        epoch.validate().unwrap();
        assert_eq!(epoch.agent_id, agent.id);
        assert_eq!(
            epoch.request.kind,
            execution::ExactMaterialKind::ModelRequest
        );
        assert!(matches!(
            epoch.outcome,
            execution::EpochOutcomeMaterial::Succeeded { .. }
        ));

        let invalid_epoch = app
            .clone()
            .oneshot(
                Request::get(
                    "/api/v1/sessions/session-reply-context/turns/turn-context-2/agent/execution/epochs/not-a-step",
                )
                .header(header::HOST, "zeus.test")
                .header(header::COOKIE, &owner.cookie_header)
                .body(Body::empty())
                .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(invalid_epoch.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            invalid_epoch.headers().get(header::CACHE_CONTROL),
            Some(&HeaderValue::from_static("no-store"))
        );
        let invalid_epoch: ProblemDetails = response_json(invalid_epoch).await;
        assert_eq!(invalid_epoch.code, "invalid_agent_epoch_step");

        let recorded = requests.lock().unwrap().clone();
        let first_context = store
            .session_agent_knowledge_context(&owner.authz, "remember alpha")
            .await
            .unwrap()
            .snapshot
            .snapshot()
            .canonical_context()
            .to_owned();
        let second_context = store
            .session_agent_knowledge_context(&owner.authz, "what did I say?")
            .await
            .unwrap()
            .snapshot
            .snapshot()
            .canonical_context()
            .to_owned();
        assert_eq!(
            recorded.len(),
            2,
            "idempotent replay must not call the provider"
        );
        assert_eq!(
            recorded[0].messages,
            vec![
                ReplyMessage::new(ReplyRole::System, store.session_agent_system_prompt(),),
                ReplyMessage::new(ReplyRole::User, "remember alpha"),
                ReplyMessage::new(ReplyRole::Context, first_context),
            ]
        );
        assert_eq!(
            recorded[1].messages,
            vec![
                ReplyMessage::new(ReplyRole::System, store.session_agent_system_prompt(),),
                ReplyMessage::new(ReplyRole::User, "remember alpha"),
                ReplyMessage::new(ReplyRole::Assistant, "durable answer 1"),
                ReplyMessage::new(ReplyRole::User, "what did I say?"),
                ReplyMessage::new(ReplyRole::Context, second_context),
            ]
        );

        drop(app);
        drop(store);
        cleanup_test_database(&path);
    }

    #[tokio::test]
    async fn session_fork_api_replays_an_exact_parent_prefix_into_new_agent_context() {
        let unique = UserId::generate().unwrap();
        let path = std::env::temp_dir().join(format!(
            "zeus-api-session-fork-{}.db",
            unique.as_str().replace(':', "-")
        ));
        let store = DemoStore::open(&path).await.unwrap();
        let owner = provision_test_owner(&store, "user-fork", "fork-owner").await;
        store
            .create_session_for_actor(
                &owner.authz,
                CreateSessionRequest {
                    id: "session-fork-parent".into(),
                    title: "Fork parent".into(),
                },
                "create-fork-parent",
            )
            .await
            .unwrap();
        let requests = Arc::new(StdMutex::new(Vec::new()));
        let app = authenticated_app_with_provider(
            store.clone(),
            false,
            Arc::new(RecordingProvider::new(Arc::clone(&requests))),
        )
        .unwrap();

        for (turn_id, message, sequence, key) in [
            ("turn-fork-parent-alpha", "remember alpha", 1, "fork-alpha"),
            ("turn-fork-parent-beta", "remember beta", 4, "fork-beta"),
        ] {
            let response = app
                .clone()
                .oneshot(
                    Request::post("/api/v1/sessions/session-fork-parent/turns")
                        .header(header::HOST, "zeus.test")
                        .header(header::ORIGIN, "http://zeus.test")
                        .header(header::COOKIE, &owner.cookie_header)
                        .header(CSRF_HEADER, &owner.csrf_token)
                        .header(header::CONTENT_TYPE, "application/json")
                        .header("idempotency-key", key)
                        .body(Body::from(
                            serde_json::json!({
                                "turn_id": turn_id,
                                "user_message": message,
                                "expected_sequence": sequence,
                            })
                            .to_string(),
                        ))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::ACCEPTED);
            let settled = wait_for_ready_session(&store, &owner.authz, "session-fork-parent").await;
            assert_eq!(settled.session.sequence, sequence + 3);
        }

        let fork_request = || {
            Request::post("/api/v1/sessions/session-fork-parent/forks")
                .header(header::HOST, "zeus.test")
                .header(header::ORIGIN, "http://zeus.test")
                .header(header::COOKIE, &owner.cookie_header)
                .header(CSRF_HEADER, &owner.csrf_token)
                .header(header::CONTENT_TYPE, "application/json")
                .header("idempotency-key", "fork-parent-at-alpha")
                .body(Body::from(
                    serde_json::json!({
                        "id": "session-fork-child",
                        "title": "Fork child",
                        "through_sequence": 4,
                    })
                    .to_string(),
                ))
                .unwrap()
        };
        let forked = app.clone().oneshot(fork_request()).await.unwrap();
        assert_eq!(forked.status(), StatusCode::CREATED);
        let forked: ForkSessionResponse = response_json(forked).await;
        assert!(!forked.replayed);
        assert_eq!(forked.session.sequence, 4);
        assert_eq!(forked.fork.parent_session_id, "session-fork-parent");
        assert_eq!(forked.fork.parent_sequence, 4);
        assert_eq!(forked.fork.inherited_turns, 1);

        let replay = app.clone().oneshot(fork_request()).await.unwrap();
        assert_eq!(replay.status(), StatusCode::OK);
        let replay: ForkSessionResponse = response_json(replay).await;
        assert!(replay.replayed);
        assert_eq!(replay.session, forked.session);
        assert_eq!(replay.fork, forked.fork);

        let second_fork = app
            .clone()
            .oneshot(
                Request::post("/api/v1/sessions/session-fork-parent/forks")
                    .header(header::HOST, "zeus.test")
                    .header(header::ORIGIN, "http://zeus.test")
                    .header(header::COOKIE, &owner.cookie_header)
                    .header(CSRF_HEADER, &owner.csrf_token)
                    .header(header::CONTENT_TYPE, "application/json")
                    .header("idempotency-key", "fork-parent-at-beta")
                    .body(Body::from(
                        serde_json::json!({
                            "id": "session-fork-child-beta",
                            "title": "Fork child at beta",
                            "through_sequence": 7,
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(second_fork.status(), StatusCode::CREATED);

        let first_page = app
            .clone()
            .oneshot(
                Request::get("/api/v1/sessions/session-fork-parent/forks?limit=1")
                    .header(header::HOST, "zeus.test")
                    .header(header::COOKIE, &owner.cookie_header)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(first_page.status(), StatusCode::OK);
        let next_cursor = first_page
            .headers()
            .get("x-zeus-next-cursor")
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned();
        let first_page: Vec<SessionForkSummary> = response_json(first_page).await;
        assert_eq!(first_page.len(), 1);

        let second_page = app
            .clone()
            .oneshot(
                Request::get(format!(
                    "/api/v1/sessions/session-fork-parent/forks?limit=1&cursor={next_cursor}"
                ))
                .header(header::HOST, "zeus.test")
                .header(header::COOKIE, &owner.cookie_header)
                .body(Body::empty())
                .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(second_page.status(), StatusCode::OK);
        assert!(second_page.headers().get("x-zeus-next-cursor").is_none());
        let second_page: Vec<SessionForkSummary> = response_json(second_page).await;
        assert_eq!(second_page.len(), 1);
        let mut catalog_ids = first_page
            .into_iter()
            .chain(second_page)
            .map(|item| item.session.id)
            .collect::<Vec<_>>();
        catalog_ids.sort();
        assert_eq!(
            catalog_ids,
            ["session-fork-child", "session-fork-child-beta"]
        );

        let detail = app
            .clone()
            .oneshot(
                Request::get("/api/v1/sessions/session-fork-child")
                    .header(header::HOST, "zeus.test")
                    .header(header::COOKIE, &owner.cookie_header)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(detail.status(), StatusCode::OK);
        let detail: SessionDetail = response_json(detail).await;
        assert_eq!(detail.fork.as_ref(), Some(&forked.fork));
        assert_eq!(detail.turns.len(), 1);
        assert_eq!(detail.turns[0].user_message, "remember alpha");

        let continued = app
            .clone()
            .oneshot(
                Request::post("/api/v1/sessions/session-fork-child/turns")
                    .header(header::HOST, "zeus.test")
                    .header(header::ORIGIN, "http://zeus.test")
                    .header(header::COOKIE, &owner.cookie_header)
                    .header(CSRF_HEADER, &owner.csrf_token)
                    .header(header::CONTENT_TYPE, "application/json")
                    .header("idempotency-key", "fork-child-continue")
                    .body(Body::from(
                        serde_json::json!({
                            "turn_id": "turn-fork-child-continue",
                            "user_message": "continue the alpha branch",
                            "expected_sequence": 4,
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(continued.status(), StatusCode::ACCEPTED);
        wait_for_ready_session(&store, &owner.authz, "session-fork-child").await;

        let recorded = requests.lock().unwrap().clone();
        assert_eq!(recorded.len(), 3);
        let branch = &recorded[2].messages;
        assert_eq!(branch[0].role, ReplyRole::System);
        assert_eq!(
            branch[1],
            ReplyMessage::new(ReplyRole::User, "remember alpha")
        );
        assert_eq!(
            branch[2],
            ReplyMessage::new(ReplyRole::Assistant, "durable answer 1")
        );
        assert_eq!(
            branch[3],
            ReplyMessage::new(ReplyRole::User, "continue the alpha branch")
        );
        assert_eq!(branch.last().unwrap().role, ReplyRole::Context);
        assert!(
            branch
                .iter()
                .all(|message| !message.content.contains("remember beta")),
            "the child must not observe parent history after its fork boundary"
        );
        store.verify_integrity().await.unwrap();

        drop(app);
        drop(store);
        cleanup_test_database(&path);
    }

    #[tokio::test]
    async fn agent_manifest_drift_is_explained_and_rejected_before_provider_execution() {
        let store = DemoStore::seeded().await.unwrap();
        let owner =
            provision_test_owner(&store, "user-manifest-drift", "manifest-drift-owner").await;
        let session_id = "session-manifest-drift";
        let turn_id = "turn-manifest-drift";
        store
            .create_session_for_actor(
                &owner.authz,
                CreateSessionRequest {
                    id: session_id.into(),
                    title: "Manifest drift".into(),
                },
                "create-manifest-drift",
            )
            .await
            .unwrap();

        let queued_manifest = store
            .session_agent_manifest(
                "queued-agent-provider",
                Some("queued-model".into()),
                AssistantReplyKind::Model,
            )
            .unwrap();
        let knowledge = store
            .session_agent_knowledge_context(&owner.authz, "do not execute after deployment drift")
            .await
            .unwrap();
        let request = ReplyRequest::with_tools(
            [
                ReplyMessage::new(ReplyRole::System, store.session_agent_system_prompt()),
                ReplyMessage::new(ReplyRole::User, "do not execute after deployment drift"),
                ReplyMessage::new(
                    ReplyRole::Context,
                    knowledge.snapshot.snapshot().canonical_context(),
                ),
            ],
            agent_tools_from_manifest(&queued_manifest),
        );
        store
            .start_turn_and_enqueue_agent_for_actor(
                &owner.authz,
                session_id,
                StartTurnRequest {
                    turn_id: turn_id.into(),
                    user_message: "do not execute after deployment drift".into(),
                    expected_sequence: 1,
                },
                "start-manifest-drift",
                AgentTurnSpec {
                    id: durable_agent_id(session_id, turn_id),
                    authz: owner.authz.clone(),
                    environment: store.session_agent_environment().to_owned(),
                    provider_name: "queued-agent-provider".into(),
                    model_name: Some("queued-model".into()),
                    request_json: persisted_agent_reply_request(&request).unwrap(),
                    manifest: queued_manifest.clone(),
                    knowledge,
                },
            )
            .await
            .unwrap();

        let provider_calls = Arc::new(AtomicUsize::new(0));
        let app = authenticated_app_with_provider(
            store.clone(),
            false,
            Arc::new(CountingProvider::new(Arc::clone(&provider_calls))),
        )
        .unwrap();
        let failed = wait_for_agent_status(
            &store,
            &owner.authz,
            session_id,
            turn_id,
            protocol::AgentTurnStatus::Failed,
        )
        .await;
        assert_eq!(provider_calls.load(Ordering::Relaxed), 0);
        assert_eq!(
            failed
                .last_error
                .as_ref()
                .and_then(|error| error.get("code"))
                .and_then(serde_json::Value::as_str),
            Some("provider_configuration_changed")
        );
        assert_eq!(
            failed.deployment_manifest_digest.as_deref(),
            Some(queued_manifest.digest.as_str())
        );

        let explanation = app
            .oneshot(
                Request::get(format!(
                    "/api/v1/sessions/{session_id}/turns/{turn_id}/agent/explain"
                ))
                .header(header::HOST, "zeus.test")
                .header(header::COOKIE, &owner.cookie_header)
                .body(Body::empty())
                .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(explanation.status(), StatusCode::OK);
        let explanation: AgentDeploymentExplainResponse = response_json(explanation).await;
        assert!(!explanation.legacy_unbound);
        assert!(!explanation.matches_current);
        let diff = explanation.diff.expect("provider drift must be explained");
        assert!(
            diff.changes
                .iter()
                .any(|change| change.path.ends_with("/provider_id"))
        );
        assert_eq!(
            explanation.persisted_manifest.unwrap().digest,
            queued_manifest.digest
        );
    }

    #[tokio::test]
    async fn agent_cancel_endpoint_is_cas_replayable_and_stops_running_models() {
        let store = DemoStore::seeded().await.unwrap();
        let (app, request_auth) = app_with_auth(store.clone()).await;
        let session_id = "session-agent-cancel-api";
        store
            .create_session_for_actor(
                &request_auth.authz,
                CreateSessionRequest {
                    id: session_id.into(),
                    title: "Agent cancellation API".into(),
                },
                "create-agent-cancel-api",
            )
            .await
            .unwrap();
        let manifest = store
            .session_agent_manifest(
                "test-provider",
                Some("test-model".into()),
                AssistantReplyKind::Model,
            )
            .unwrap();

        let enqueue = |turn_id: &str, message: &str, expected_sequence: u64| {
            let store = store.clone();
            let authz = request_auth.authz.clone();
            let manifest = manifest.clone();
            let turn_id = turn_id.to_owned();
            let message = message.to_owned();
            async move {
                let knowledge = store
                    .session_agent_knowledge_context(&authz, &message)
                    .await
                    .unwrap();
                let request = ReplyRequest::with_tools(
                    [
                        ReplyMessage::new(ReplyRole::System, store.session_agent_system_prompt()),
                        ReplyMessage::new(ReplyRole::User, message.clone()),
                        ReplyMessage::new(
                            ReplyRole::Context,
                            knowledge.snapshot.snapshot().canonical_context(),
                        ),
                    ],
                    agent_tools_from_manifest(&manifest),
                );
                store
                    .start_turn_and_enqueue_agent_for_actor(
                        &authz,
                        session_id,
                        StartTurnRequest {
                            turn_id: turn_id.clone(),
                            user_message: message,
                            expected_sequence,
                        },
                        &format!("start-{turn_id}"),
                        AgentTurnSpec {
                            id: durable_agent_id(session_id, &turn_id),
                            authz: authz.clone(),
                            environment: store.session_agent_environment().to_owned(),
                            provider_name: "test-provider".into(),
                            model_name: Some("test-model".into()),
                            request_json: persisted_agent_reply_request(&request).unwrap(),
                            manifest,
                            knowledge,
                        },
                    )
                    .await
                    .unwrap()
            }
        };

        let queued = enqueue("turn-agent-cancel-api", "cancel before provider start", 1).await;
        let cancel_uri =
            format!("/api/v1/sessions/{session_id}/turns/turn-agent-cancel-api/agent/cancel");
        let response = app
            .clone()
            .oneshot(
                Request::put(&cancel_uri)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        serde_json::json!({"expected_revision": queued.agent.revision}).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(header::CACHE_CONTROL),
            Some(&HeaderValue::from_static("no-store"))
        );
        let cancelled: CancelAgentTurnResponse = response_json(response).await;
        assert!(!cancelled.replayed);
        assert_eq!(cancelled.agent.status, protocol::AgentTurnStatus::Failed);
        assert_eq!(
            cancelled.turn.status,
            protocol::SessionTurnStatus::Interrupted
        );

        let replay = app
            .clone()
            .oneshot(
                Request::put(&cancel_uri)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        serde_json::json!({"expected_revision": queued.agent.revision}).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(replay.status(), StatusCode::OK);
        let replay: CancelAgentTurnResponse = response_json(replay).await;
        assert!(replay.replayed);
        assert_eq!(replay.agent, cancelled.agent);
        assert_eq!(replay.event, cancelled.event);

        let invalid = app
            .clone()
            .oneshot(
                Request::put(&cancel_uri)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(r#"{"expected_revision":0}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(invalid.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            response_json::<ProblemDetails>(invalid).await.code,
            "invalid_agent_revision"
        );

        let resumed = store
            .resume_session_for_actor(
                &request_auth.authz,
                session_id,
                ResumeSessionRequest {
                    expected_sequence: cancelled.event.sequence,
                },
                "resume-after-agent-cancel-api",
            )
            .await
            .unwrap();
        let started = enqueue(
            "turn-agent-cancel-started-api",
            "cancel after provider start",
            resumed.session.sequence,
        )
        .await;
        assert!(matches!(
            store.claim_next_agent_model(&manifest).await.unwrap(),
            AgentModelClaimOutcome::Claimed(_)
        ));
        let started_detail = store
            .agent_turn_detail_for_actor(
                &request_auth.authz,
                session_id,
                "turn-agent-cancel-started-api",
            )
            .await
            .unwrap();
        assert!(started_detail.revision > started.agent.revision);
        let running_cancelled = app
            .oneshot(
                Request::put(format!(
                    "/api/v1/sessions/{session_id}/turns/turn-agent-cancel-started-api/agent/cancel"
                ))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::json!({"expected_revision": started_detail.revision}).to_string(),
                ))
                .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(running_cancelled.status(), StatusCode::OK);
        let running_cancelled: CancelAgentTurnResponse = response_json(running_cancelled).await;
        assert_eq!(
            running_cancelled.agent.status,
            protocol::AgentTurnStatus::Failed
        );
        assert!(matches!(
            running_cancelled.event.data,
            protocol::SessionEventData::TurnInterrupted { ref reason, .. }
                if reason == "agent turn was cancelled while model execution was in progress"
        ));
        store.readiness().await.unwrap();
    }

    #[tokio::test]
    async fn queued_agent_executes_its_bound_registered_provider_after_default_changes() {
        let store = DemoStore::seeded().await.unwrap();
        let owner =
            provision_test_owner(&store, "user-provider-binding", "provider-binding-owner").await;
        let session_id = "session-provider-binding";
        let turn_id = "turn-provider-binding";
        store
            .create_session_for_actor(
                &owner.authz,
                CreateSessionRequest {
                    id: session_id.into(),
                    title: "Bound provider recovery".into(),
                },
                "create-bound-provider-session",
            )
            .await
            .unwrap();
        let manifest = store
            .session_agent_manifest(
                "test-recording-provider",
                Some("test-model".into()),
                AssistantReplyKind::Model,
            )
            .unwrap();
        let knowledge = store
            .session_agent_knowledge_context(&owner.authz, "execute the durable binding")
            .await
            .unwrap();
        let request = ReplyRequest::with_tools(
            [
                ReplyMessage::new(ReplyRole::System, store.session_agent_system_prompt()),
                ReplyMessage::new(ReplyRole::User, "execute the durable binding"),
                ReplyMessage::new(
                    ReplyRole::Context,
                    knowledge.snapshot.snapshot().canonical_context(),
                ),
            ],
            agent_tools_from_manifest(&manifest),
        );
        store
            .start_turn_and_enqueue_agent_for_actor(
                &owner.authz,
                session_id,
                StartTurnRequest {
                    turn_id: turn_id.into(),
                    user_message: "execute the durable binding".into(),
                    expected_sequence: 1,
                },
                "queue-bound-provider-turn",
                AgentTurnSpec {
                    id: durable_agent_id(session_id, turn_id),
                    authz: owner.authz.clone(),
                    environment: store.session_agent_environment().to_owned(),
                    provider_name: "test-recording-provider".into(),
                    model_name: Some("test-model".into()),
                    request_json: persisted_agent_reply_request(&request).unwrap(),
                    manifest,
                    knowledge,
                },
            )
            .await
            .unwrap();

        let default_calls = Arc::new(AtomicUsize::new(0));
        let bound_requests = Arc::new(StdMutex::new(Vec::new()));
        let app = authenticated_app_with_provider_registry_and_ingress(
            store.clone(),
            IngressPolicy::direct(false),
            Arc::new(CountingProvider::new(Arc::clone(&default_calls))),
            vec![Arc::new(RecordingProvider::new(Arc::clone(
                &bound_requests,
            )))],
        )
        .unwrap();
        let succeeded = wait_for_agent_status(
            &store,
            &owner.authz,
            session_id,
            turn_id,
            protocol::AgentTurnStatus::Succeeded,
        )
        .await;
        assert_eq!(succeeded.model_steps, 1);
        assert_eq!(default_calls.load(Ordering::Relaxed), 0);
        assert_eq!(bound_requests.lock().unwrap().len(), 1);
        drop(app);
    }

    #[tokio::test]
    async fn agent_tool_approval_executes_once_and_continues_to_final() {
        let unique = UserId::generate().unwrap();
        let root = std::env::temp_dir().join(format!(
            "zeus-api-agent-tool-{}",
            unique.as_str().replace(':', "-")
        ));
        let path = root.join("zeus.db");
        let marker_root = root.join("markers");
        std::fs::create_dir_all(&root).unwrap();
        let store = DemoStore::open_local(&path, &marker_root).await.unwrap();
        let owner = provision_test_owner(&store, "user-agent-tool", "agent-tool-owner").await;
        store
            .create_session_for_actor(
                &owner.authz,
                CreateSessionRequest {
                    id: "session-agent-tool".into(),
                    title: "Approved Agent tool".into(),
                },
                "create-agent-tool",
            )
            .await
            .unwrap();
        let requests = Arc::new(StdMutex::new(Vec::new()));
        let app = authenticated_app_with_provider(
            store.clone(),
            false,
            Arc::new(ToolThenFinalProvider::new(Arc::clone(&requests))),
        )
        .unwrap();

        let started = app
            .clone()
            .oneshot(
                Request::post("/api/v1/sessions/session-agent-tool/turns")
                    .header(header::HOST, "zeus.test")
                    .header(header::ORIGIN, "http://zeus.test")
                    .header(header::COOKIE, &owner.cookie_header)
                    .header(CSRF_HEADER, &owner.csrf_token)
                    .header(header::CONTENT_TYPE, "application/json")
                    .header("idempotency-key", "start-agent-tool")
                    .body(Body::from(
                        serde_json::json!({
                            "turn_id": "turn-agent-tool",
                            "user_message": "write the approved marker",
                            "expected_sequence": 1,
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(started.status(), StatusCode::ACCEPTED);

        let waiting = wait_for_agent_status(
            &store,
            &owner.authz,
            "session-agent-tool",
            "turn-agent-tool",
            protocol::AgentTurnStatus::WaitingApproval,
        )
        .await;
        let call_id = waiting.pending_call_id.clone().unwrap();
        assert_eq!(waiting.model_steps, 1);
        assert_eq!(waiting.calls.len(), 1);
        assert_eq!(waiting.calls[0].call_id, call_id);
        assert_eq!(
            waiting.calls[0].status,
            AgentToolCallStatus::WaitingApproval
        );
        assert_eq!(std::fs::read_dir(&marker_root).unwrap().count(), 0);

        let approved = app
            .clone()
            .oneshot(
                Request::post(format!(
                    "/api/v1/sessions/session-agent-tool/turns/turn-agent-tool/approvals/{call_id}/decision"
                ))
                .header(header::HOST, "zeus.test")
                .header(header::ORIGIN, "http://zeus.test")
                .header(header::COOKIE, &owner.cookie_header)
                .header(CSRF_HEADER, &owner.csrf_token)
                .header(header::CONTENT_TYPE, "application/json")
                .header("idempotency-key", "approve-agent-tool")
                .body(Body::from(
                    serde_json::json!({
                        "decision": "approve",
                        "note": "execute the exact persisted call",
                        "idempotency_key": "approve-agent-tool",
                    })
                    .to_string(),
                ))
                .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(approved.status(), StatusCode::OK);
        let approved: AgentReviewResponse = response_json(approved).await;
        assert!(!approved.replayed);
        assert_eq!(approved.call.call_id, call_id);
        assert_eq!(approved.call.status, AgentToolCallStatus::Queued);

        let session = wait_for_ready_session(&store, &owner.authz, "session-agent-tool").await;
        assert_eq!(session.session.sequence, 4);
        let agent = wait_for_agent_status(
            &store,
            &owner.authz,
            "session-agent-tool",
            "turn-agent-tool",
            protocol::AgentTurnStatus::Succeeded,
        )
        .await;
        assert_eq!(agent.model_steps, 2);
        assert_eq!(agent.tool_calls, 1);
        assert_eq!(agent.calls.len(), 1);
        assert_eq!(agent.calls[0].status, AgentToolCallStatus::Succeeded);
        assert!(agent.calls[0].output.is_some());
        assert_eq!(std::fs::read_dir(&marker_root).unwrap().count(), 1);

        let recorded = requests.lock().unwrap().clone();
        let context = store
            .session_agent_knowledge_context(&owner.authz, "write the approved marker")
            .await
            .unwrap()
            .snapshot
            .snapshot()
            .canonical_context()
            .to_owned();
        assert_eq!(recorded.len(), 2);
        assert_eq!(
            recorded[0].messages,
            vec![
                ReplyMessage::new(ReplyRole::System, store.session_agent_system_prompt(),),
                ReplyMessage::new(ReplyRole::User, "write the approved marker"),
                ReplyMessage::new(ReplyRole::Context, context),
            ]
        );
        assert_eq!(recorded[1].messages.len(), 5);
        assert_eq!(recorded[1].messages[0], recorded[0].messages[0]);
        assert_eq!(recorded[1].messages[1], recorded[0].messages[1]);
        assert_eq!(recorded[1].messages[2], recorded[0].messages[2]);
        let provider_call = recorded[1].messages[3].tool_call.as_ref().unwrap();
        assert_eq!(provider_call.id, "provider-call-approved-1");
        assert_eq!(provider_call.name, agent.calls[0].tool);
        assert_eq!(provider_call.arguments, agent.calls[0].arguments);
        let tool_result = &recorded[1].messages[4];
        assert_eq!(tool_result.role, ReplyRole::Tool);
        assert_eq!(
            tool_result.tool_call_id.as_deref(),
            Some("provider-call-approved-1")
        );
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&tool_result.content).unwrap(),
            agent.calls[0].output.clone().unwrap()
        );

        drop(app);
        drop(store);
        tokio::task::yield_now().await;
        cleanup_test_database(&path);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[tokio::test]
    async fn agent_todo_write_persists_and_continues_without_approval() {
        let store = DemoStore::seeded().await.unwrap();
        let owner = provision_test_owner(&store, "user-agent-todo", "agent-todo-owner").await;
        store
            .create_session_for_actor(
                &owner.authz,
                CreateSessionRequest {
                    id: "session-agent-todo".into(),
                    title: "Durable Agent plan".into(),
                },
                "create-agent-todo",
            )
            .await
            .unwrap();
        let requests = Arc::new(StdMutex::new(Vec::new()));
        let app = authenticated_app_with_provider(
            store.clone(),
            false,
            Arc::new(TodoThenFinalProvider::new(Arc::clone(&requests))),
        )
        .unwrap();

        let started = app
            .clone()
            .oneshot(
                Request::post("/api/v1/sessions/session-agent-todo/turns")
                    .header(header::HOST, "zeus.test")
                    .header(header::ORIGIN, "http://zeus.test")
                    .header(header::COOKIE, &owner.cookie_header)
                    .header(CSRF_HEADER, &owner.csrf_token)
                    .header(header::CONTENT_TYPE, "application/json")
                    .header("idempotency-key", "start-agent-todo")
                    .body(Body::from(
                        serde_json::json!({
                            "turn_id": "turn-agent-todo",
                            "user_message": "make and execute a durable plan",
                            "expected_sequence": 1,
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(started.status(), StatusCode::ACCEPTED);

        let session = wait_for_ready_session(&store, &owner.authz, "session-agent-todo").await;
        assert_eq!(session.session.sequence, 4);
        let agent = wait_for_agent_status(
            &store,
            &owner.authz,
            "session-agent-todo",
            "turn-agent-todo",
            protocol::AgentTurnStatus::Succeeded,
        )
        .await;
        assert_eq!(agent.model_steps, 2);
        assert_eq!(agent.tool_calls, 1);
        assert_eq!(agent.calls.len(), 1);
        assert_eq!(agent.calls[0].tool, planning::TODO_WRITE_TOOL_NAME);
        assert_eq!(agent.calls[0].status, AgentToolCallStatus::Succeeded);
        assert!(!agent.calls[0].approval_required);
        let todo = agent
            .todo
            .expect("todo_write must publish its durable projection");
        assert_eq!(todo.revision, 1);
        assert_eq!(todo.call_id, agent.calls[0].call_id);
        assert_eq!(todo.todos.len(), 2);
        assert_eq!(todo.todos[0].content, "inspect durable state");
        assert_eq!(todo.todos[0].status, protocol::AgentTodoStatus::Completed);
        assert_eq!(todo.todos[1].status, protocol::AgentTodoStatus::InProgress);

        let recorded = requests.lock().unwrap().clone();
        assert_eq!(recorded.len(), 2);
        let tool_result = recorded[1]
            .messages
            .iter()
            .find(|message| message.role == ReplyRole::Tool)
            .expect("the continuation must contain the exact todo result");
        let result: serde_json::Value = serde_json::from_str(&tool_result.content).unwrap();
        assert_eq!(result["revision"], 1);
        assert_eq!(result["digest"], todo.digest);
        assert_eq!(result["todos"][1]["status"], "in_progress");
        drop(app);
    }

    #[tokio::test]
    async fn agent_spawn_and_list_agents_are_durable_without_approval() {
        let store = DemoStore::seeded().await.unwrap();
        let owner =
            provision_test_owner(&store, "user-agent-list-agents", "agent-list-agents-owner").await;
        store
            .create_session_for_actor(
                &owner.authz,
                CreateSessionRequest {
                    id: "session-agent-list-agents".into(),
                    title: "Durable child catalog".into(),
                },
                "create-agent-list-agents",
            )
            .await
            .unwrap();
        store
            .fork_session_for_actor(
                &owner.authz,
                "session-agent-list-agents",
                ForkSessionRequest {
                    id: "session-manual-fork-not-agent".into(),
                    title: "Manual fork".into(),
                    through_sequence: 1,
                },
                "fork-manual-not-agent",
            )
            .await
            .unwrap();

        let requests = Arc::new(StdMutex::new(Vec::new()));
        let app = authenticated_app_with_provider(
            store.clone(),
            false,
            Arc::new(SpawnListThenFinalProvider::new(Arc::clone(&requests))),
        )
        .unwrap();
        let started = app
            .clone()
            .oneshot(
                Request::post("/api/v1/sessions/session-agent-list-agents/turns")
                    .header(header::HOST, "zeus.test")
                    .header(header::ORIGIN, "http://zeus.test")
                    .header(header::COOKIE, &owner.cookie_header)
                    .header(CSRF_HEADER, &owner.csrf_token)
                    .header(header::CONTENT_TYPE, "application/json")
                    .header("idempotency-key", "start-agent-list-agents")
                    .body(Body::from(
                        serde_json::json!({
                            "turn_id": "turn-agent-list-agents",
                            "user_message": "inspect every direct child agent",
                            "expected_sequence": 1,
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(started.status(), StatusCode::ACCEPTED);

        wait_for_ready_session(&store, &owner.authz, "session-agent-list-agents").await;
        let agent = wait_for_agent_status(
            &store,
            &owner.authz,
            "session-agent-list-agents",
            "turn-agent-list-agents",
            protocol::AgentTurnStatus::Succeeded,
        )
        .await;
        assert_eq!(agent.model_steps, 5);
        assert_eq!(agent.tool_calls, 4);
        assert_eq!(
            agent
                .calls
                .iter()
                .filter(|call| call.tool == subagents::SPAWN_AGENT_TOOL_NAME)
                .count(),
            2
        );
        assert_eq!(
            agent
                .calls
                .iter()
                .filter(|call| call.tool == subagents::LIST_AGENTS_TOOL_NAME)
                .count(),
            2
        );
        assert!(agent.calls.iter().all(|call| {
            call.status == AgentToolCallStatus::Succeeded && !call.approval_required
        }));

        let recorded = requests.lock().unwrap().clone();
        assert_eq!(recorded.len(), 7);
        let parent_requests = recorded
            .iter()
            .filter(|request| {
                request.messages.iter().any(|message| {
                    message.role == ReplyRole::User
                        && message.content == "inspect every direct child agent"
                })
            })
            .collect::<Vec<_>>();
        assert_eq!(parent_requests.len(), 5);
        let pages = [&parent_requests[3], &parent_requests[4]]
            .into_iter()
            .map(|request| {
                request
                    .messages
                    .iter()
                    .rev()
                    .find(|message| message.role == ReplyRole::Tool)
                    .map(|message| {
                        serde_json::from_str::<subagents::ListAgentsResult>(&message.content)
                            .unwrap()
                    })
                    .unwrap()
            })
            .collect::<Vec<_>>();
        assert_eq!(pages[0].agents.len(), 1);
        assert!(pages[0].next_cursor.is_some());
        assert_eq!(pages[1].agents.len(), 1);
        assert!(pages[1].next_cursor.is_none());
        let ids = pages
            .iter()
            .flat_map(|page| page.agents.iter())
            .map(|agent| agent.session.id.as_str())
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(ids.len(), 2);
        assert!(!ids.contains("session-manual-fork-not-agent"));
        for child_id in ids {
            let child = wait_for_ready_session(&store, &owner.authz, child_id).await;
            assert_eq!(child.turns.len(), 1);
            assert!(matches!(
                child.turns[0].user_message.as_str(),
                "inspect child alpha" | "inspect child beta"
            ));
        }
        store.verify_integrity().await.unwrap();
        drop(app);
    }

    #[tokio::test]
    async fn agent_goal_read_create_persists_and_continues_without_approval() {
        let store = DemoStore::seeded().await.unwrap();
        let owner = provision_test_owner(&store, "user-agent-goal", "agent-goal-owner").await;
        store
            .create_session_for_actor(
                &owner.authz,
                CreateSessionRequest {
                    id: "session-agent-goal".into(),
                    title: "Durable Agent goal".into(),
                },
                "create-agent-goal",
            )
            .await
            .unwrap();
        let requests = Arc::new(StdMutex::new(Vec::new()));
        let app = authenticated_app_with_provider(
            store.clone(),
            false,
            Arc::new(GoalReadCreateThenFinalProvider::new(Arc::clone(&requests))),
        )
        .unwrap();

        let started = app
            .clone()
            .oneshot(
                Request::post("/api/v1/sessions/session-agent-goal/turns")
                    .header(header::HOST, "zeus.test")
                    .header(header::ORIGIN, "http://zeus.test")
                    .header(header::COOKIE, &owner.cookie_header)
                    .header(CSRF_HEADER, &owner.csrf_token)
                    .header(header::CONTENT_TYPE, "application/json")
                    .header("idempotency-key", "start-agent-goal")
                    .body(Body::from(
                        serde_json::json!({
                            "turn_id": "turn-agent-goal",
                            "user_message": "create a durable completion goal",
                            "expected_sequence": 1,
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(started.status(), StatusCode::ACCEPTED);

        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                if requests.lock().unwrap().len() >= 6 {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("the armed Goal must admit and finish its first round");
        let session = wait_for_ready_session(&store, &owner.authz, "session-agent-goal").await;
        assert_eq!(session.session.sequence, 7);
        assert_eq!(session.turns.len(), 2);
        let agent = wait_for_agent_status(
            &store,
            &owner.authz,
            "session-agent-goal",
            "turn-agent-goal",
            protocol::AgentTurnStatus::Succeeded,
        )
        .await;
        assert_eq!(agent.model_steps, 3);
        assert_eq!(agent.tool_calls, 2);
        assert_eq!(agent.calls[0].tool, goals::GET_GOAL_TOOL_NAME);
        assert_eq!(agent.calls[1].tool, goals::CREATE_GOAL_TOOL_NAME);
        assert!(agent.calls.iter().all(|call| {
            call.status == AgentToolCallStatus::Succeeded && !call.approval_required
        }));
        let goal = agent
            .goal
            .expect("create_goal must publish its durable Session projection");
        assert_eq!(goal.revision, 2);
        assert_eq!(goal.objective, "Deliver the durable Goal core");
        assert_eq!(goal.phase, protocol::AgentGoalPhase::Completed);
        assert_eq!(goal.rounds_started, 1);
        assert_eq!(goal.max_rounds, 32);
        assert_ne!(goal.call_id, agent.calls[1].call_id);

        let round_turn = session
            .turns
            .iter()
            .find(|turn| turn.user_message.starts_with("<goal_round>\n"))
            .expect("the Goal round must be a real Session turn");
        let round_agent = wait_for_agent_status(
            &store,
            &owner.authz,
            "session-agent-goal",
            &round_turn.id,
            protocol::AgentTurnStatus::Succeeded,
        )
        .await;
        assert_eq!(round_agent.model_steps, 3);
        assert_eq!(round_agent.tool_calls, 2);
        assert_eq!(round_agent.calls[0].tool, goals::GET_GOAL_TOOL_NAME);
        assert_eq!(round_agent.calls[1].tool, goals::UPDATE_GOAL_TOOL_NAME);
        assert!(round_agent.calls.iter().all(|call| {
            call.status == AgentToolCallStatus::Succeeded && !call.approval_required
        }));

        let recorded = requests.lock().unwrap().clone();
        assert_eq!(recorded.len(), 6);
        let read_result = recorded[1]
            .messages
            .iter()
            .find(|message| message.role == ReplyRole::Tool)
            .expect("the first continuation must contain the Goal read result");
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&read_result.content).unwrap(),
            serde_json::json!({"goal": null})
        );
        let create_result = recorded[2]
            .messages
            .iter()
            .rev()
            .find(|message| message.role == ReplyRole::Tool)
            .expect("the second continuation must contain the Goal create result");
        let create_result: serde_json::Value =
            serde_json::from_str(&create_result.content).unwrap();
        assert_eq!(create_result["goal"]["id"], goal.id);
        assert_eq!(create_result["goal"]["revision"], 1);
        assert_eq!(create_result["goal"]["phase"], "active");
        assert_eq!(create_result["activation"], "armed");
        let round_prompt = recorded[3]
            .messages
            .iter()
            .rev()
            .find(|message| message.role == ReplyRole::User)
            .expect("the Goal round must contain its exact driver prompt");
        assert_eq!(round_prompt.content, round_turn.user_message);
        assert!(round_prompt.content.contains("Round: 1/32"));
        let completed_result = recorded[5]
            .messages
            .iter()
            .rev()
            .find(|message| message.role == ReplyRole::Tool)
            .expect("the round completion must contain its exact Goal result");
        let completed_result: serde_json::Value =
            serde_json::from_str(&completed_result.content).unwrap();
        assert_eq!(completed_result["goal"]["revision"], 2);
        assert_eq!(completed_result["goal"]["rounds_started"], 1);
        assert_eq!(completed_result["goal"]["phase"], "completed");
        assert_eq!(completed_result["activation"], "disarmed");
        store.readiness().await.unwrap();
        drop(app);
    }

    #[tokio::test]
    async fn goal_round_provider_failure_disarms_without_retry_and_restart_stays_idle() {
        let unique = UserId::generate().unwrap();
        let path = std::env::temp_dir().join(format!(
            "zeus-api-goal-round-failure-{}.db",
            unique.as_str().replace(':', "-")
        ));
        let store = DemoStore::open(&path).await.unwrap();
        let owner = provision_test_owner(
            &store,
            "user-goal-round-failure",
            "goal-round-failure-owner",
        )
        .await;
        let session_id = "session-goal-round-failure";
        store
            .create_session_for_actor(
                &owner.authz,
                CreateSessionRequest {
                    id: session_id.into(),
                    title: "Goal round failure".into(),
                },
                "create-goal-round-failure",
            )
            .await
            .unwrap();
        let requests = Arc::new(StdMutex::new(Vec::new()));
        let app = authenticated_app_with_provider(
            store.clone(),
            false,
            Arc::new(GoalCreateThenRoundTerminalProvider::new(
                Arc::clone(&requests),
                GoalRoundTerminal::KnownProviderFailure,
            )),
        )
        .unwrap();

        let started = app
            .clone()
            .oneshot(
                Request::post(format!("/api/v1/sessions/{session_id}/turns"))
                    .header(header::HOST, "zeus.test")
                    .header(header::ORIGIN, "http://zeus.test")
                    .header(header::COOKIE, &owner.cookie_header)
                    .header(CSRF_HEADER, &owner.csrf_token)
                    .header(header::CONTENT_TYPE, "application/json")
                    .header("idempotency-key", "start-goal-round-failure")
                    .body(Body::from(
                        serde_json::json!({
                            "turn_id": "turn-goal-round-failure",
                            "user_message": "Create a bounded Goal and continue it",
                            "expected_sequence": 1,
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(started.status(), StatusCode::ACCEPTED);

        let session = wait_for_session_state_and_turns(
            &store,
            &owner.authz,
            session_id,
            SessionStatus::NeedsAttention,
            2,
        )
        .await;
        let round_turn = session
            .turns
            .iter()
            .find(|turn| turn.user_message.starts_with("<goal_round>\n"))
            .unwrap();
        let round_agent = wait_for_agent_status(
            &store,
            &owner.authz,
            session_id,
            &round_turn.id,
            protocol::AgentTurnStatus::Failed,
        )
        .await;
        let goal = round_agent.goal.unwrap();
        assert_eq!(goal.phase, protocol::AgentGoalPhase::Active);
        assert_eq!(goal.rounds_started, 1);
        assert_eq!(goal.max_rounds, 1);
        assert_eq!(
            round_agent.last_error.unwrap()["code"],
            "provider_request_invalid"
        );
        wait_for_no_armed_goals(&store).await;
        assert_eq!(requests.lock().unwrap().len(), 3);
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(requests.lock().unwrap().len(), 3);

        drop(app);
        drop(store);
        tokio::task::yield_now().await;

        let reopened = DemoStore::open(&path).await.unwrap();
        assert!(reopened.armed_session_goals().await.is_empty());
        let restart_calls = Arc::new(AtomicUsize::new(0));
        let reopened_app = authenticated_app_with_provider(
            reopened.clone(),
            false,
            Arc::new(CountingProvider::new(Arc::clone(&restart_calls))),
        )
        .unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(restart_calls.load(Ordering::Relaxed), 0);
        let persisted = reopened
            .agent_turn_detail_for_actor(&owner.authz, session_id, &round_turn.id)
            .await
            .unwrap();
        assert_eq!(
            persisted.goal.unwrap().phase,
            protocol::AgentGoalPhase::Active
        );

        drop(reopened_app);
        drop(reopened);
        cleanup_test_database(&path);
    }

    #[tokio::test]
    async fn goal_round_limit_disarms_without_fabricating_a_terminal_goal() {
        let store = DemoStore::seeded().await.unwrap();
        let owner =
            provision_test_owner(&store, "user-goal-round-limit", "goal-round-limit-owner").await;
        let session_id = "session-goal-round-limit";
        store
            .create_session_for_actor(
                &owner.authz,
                CreateSessionRequest {
                    id: session_id.into(),
                    title: "Goal round limit".into(),
                },
                "create-goal-round-limit",
            )
            .await
            .unwrap();
        let requests = Arc::new(StdMutex::new(Vec::new()));
        let app = authenticated_app_with_provider(
            store.clone(),
            false,
            Arc::new(GoalCreateThenRoundTerminalProvider::new(
                Arc::clone(&requests),
                GoalRoundTerminal::FinalAtLimit,
            )),
        )
        .unwrap();

        let started = app
            .clone()
            .oneshot(
                Request::post(format!("/api/v1/sessions/{session_id}/turns"))
                    .header(header::HOST, "zeus.test")
                    .header(header::ORIGIN, "http://zeus.test")
                    .header(header::COOKIE, &owner.cookie_header)
                    .header(CSRF_HEADER, &owner.csrf_token)
                    .header(header::CONTENT_TYPE, "application/json")
                    .header("idempotency-key", "start-goal-round-limit")
                    .body(Body::from(
                        serde_json::json!({
                            "turn_id": "turn-goal-round-limit",
                            "user_message": "Use exactly one autonomous Goal round",
                            "expected_sequence": 1,
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(started.status(), StatusCode::ACCEPTED);

        let session = wait_for_session_state_and_turns(
            &store,
            &owner.authz,
            session_id,
            SessionStatus::Ready,
            2,
        )
        .await;
        let round_turn = session
            .turns
            .iter()
            .find(|turn| turn.user_message.starts_with("<goal_round>\n"))
            .unwrap();
        let round_agent = wait_for_agent_status(
            &store,
            &owner.authz,
            session_id,
            &round_turn.id,
            protocol::AgentTurnStatus::Succeeded,
        )
        .await;
        let goal = round_agent.goal.unwrap();
        assert_eq!(goal.phase, protocol::AgentGoalPhase::Active);
        assert_eq!(goal.rounds_started, 1);
        assert_eq!(goal.max_rounds, 1);
        assert!(goal.blocker.is_none());
        wait_for_no_armed_goals(&store).await;
        assert_eq!(requests.lock().unwrap().len(), 3);
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(requests.lock().unwrap().len(), 3);
        store.readiness().await.unwrap();
        drop(app);
    }

    #[tokio::test]
    async fn isolated_terminal_open_and_send_each_wait_for_approval_and_preserve_agent_scope() {
        let unique = UserId::generate().unwrap();
        let root = std::env::temp_dir().join(format!(
            "zeus-api-terminal-agent-{}",
            unique.as_str().replace(':', "-")
        ));
        let path = root.join("zeus.db");
        let marker_root = root.join("markers");
        std::fs::create_dir_all(&root).unwrap();
        let backend_actions = Arc::new(StdMutex::new(Vec::new()));
        let terminal_service = Arc::new(
            TerminalService::new([Arc::new(RecordingTerminalBackend {
                actions: Arc::clone(&backend_actions),
                hang_send: false,
            }) as Arc<dyn TerminalBackend>])
            .unwrap(),
        );
        let store = DemoStore::open_local_with_terminal(&path, &marker_root, terminal_service)
            .await
            .unwrap();
        let owner = provision_test_owner(&store, "user-terminal-agent", "terminal-owner").await;
        store
            .create_session_for_actor(
                &owner.authz,
                CreateSessionRequest {
                    id: "session-terminal-agent".into(),
                    title: "Use isolated terminal".into(),
                },
                "create-terminal-agent",
            )
            .await
            .unwrap();
        let requests = Arc::new(StdMutex::new(Vec::new()));
        let app = authenticated_app_with_provider(
            store.clone(),
            false,
            Arc::new(TerminalOpenSendThenFinalProvider::new(Arc::clone(
                &requests,
            ))),
        )
        .unwrap();

        let started = app
            .clone()
            .oneshot(
                Request::post("/api/v1/sessions/session-terminal-agent/turns")
                    .header(header::HOST, "zeus.test")
                    .header(header::ORIGIN, "http://zeus.test")
                    .header(header::COOKIE, &owner.cookie_header)
                    .header(CSRF_HEADER, &owner.csrf_token)
                    .header(header::CONTENT_TYPE, "application/json")
                    .header("idempotency-key", "start-terminal-agent")
                    .body(Body::from(
                        serde_json::json!({
                            "turn_id": "turn-terminal-agent",
                            "user_message": "open an isolated terminal and run echo zeus",
                            "expected_sequence": 1,
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(started.status(), StatusCode::ACCEPTED);

        let waiting_open = wait_for_agent_status(
            &store,
            &owner.authz,
            "session-terminal-agent",
            "turn-terminal-agent",
            protocol::AgentTurnStatus::WaitingApproval,
        )
        .await;
        let open_call_id = waiting_open.pending_call_id.clone().unwrap();
        assert_eq!(waiting_open.calls.len(), 1);
        assert_eq!(waiting_open.calls[0].tool, TEST_TERMINAL_OPEN_TOOL_NAME);
        assert!(waiting_open.calls[0].approval_required);
        assert!(backend_actions.lock().unwrap().is_empty());

        let approved_open = app
            .clone()
            .oneshot(
                Request::post(format!(
                    "/api/v1/sessions/session-terminal-agent/turns/turn-terminal-agent/approvals/{open_call_id}/decision"
                ))
                .header(header::HOST, "zeus.test")
                .header(header::ORIGIN, "http://zeus.test")
                .header(header::COOKIE, &owner.cookie_header)
                .header(CSRF_HEADER, &owner.csrf_token)
                .header(header::CONTENT_TYPE, "application/json")
                .header("idempotency-key", "approve-terminal-open")
                .body(Body::from(
                    serde_json::json!({
                        "decision": "approve",
                        "note": "open only the exact isolated terminal",
                        "idempotency_key": "approve-terminal-open",
                    })
                    .to_string(),
                ))
                .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(approved_open.status(), StatusCode::OK);

        let waiting_send = wait_for_agent_status(
            &store,
            &owner.authz,
            "session-terminal-agent",
            "turn-terminal-agent",
            protocol::AgentTurnStatus::WaitingApproval,
        )
        .await;
        let send_call_id = waiting_send.pending_call_id.clone().unwrap();
        assert_ne!(send_call_id, open_call_id);
        assert_eq!(waiting_send.calls.len(), 2);
        assert_eq!(waiting_send.calls[1].tool, TEST_TERMINAL_SEND_TOOL_NAME);
        assert!(waiting_send.calls[1].approval_required);
        {
            let actions = backend_actions.lock().unwrap();
            assert_eq!(actions.len(), 1);
            let RecordedTerminalAction::Spawn(request) = &actions[0] else {
                panic!("terminal open must be the first isolated backend action");
            };
            assert_eq!(request.session_id, "pty-1");
            assert_eq!(request.cwd, ".");
            assert_eq!(request.owner.account_id, owner.authz.account_id.as_str());
            assert_eq!(request.owner.actor_id, owner.authz.user_id.as_str());
            assert_eq!(request.owner.session_id, "session-terminal-agent");
            assert_eq!(request.owner.turn_id, "turn-terminal-agent");
            assert_eq!(
                request.owner.agent_id,
                durable_agent_id("session-terminal-agent", "turn-terminal-agent")
            );
        }

        let approved_send = app
            .clone()
            .oneshot(
                Request::post(format!(
                    "/api/v1/sessions/session-terminal-agent/turns/turn-terminal-agent/approvals/{send_call_id}/decision"
                ))
                .header(header::HOST, "zeus.test")
                .header(header::ORIGIN, "http://zeus.test")
                .header(header::COOKIE, &owner.cookie_header)
                .header(CSRF_HEADER, &owner.csrf_token)
                .header(header::CONTENT_TYPE, "application/json")
                .header("idempotency-key", "approve-terminal-send")
                .body(Body::from(
                    serde_json::json!({
                        "decision": "approve",
                        "note": "send only the exact persisted command",
                        "idempotency_key": "approve-terminal-send",
                    })
                    .to_string(),
                ))
                .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(approved_send.status(), StatusCode::OK);

        let session = wait_for_ready_session(&store, &owner.authz, "session-terminal-agent").await;
        assert_eq!(
            session.turns[0].assistant_message.as_deref(),
            Some("isolated terminal command completed")
        );
        let agent = wait_for_agent_status(
            &store,
            &owner.authz,
            "session-terminal-agent",
            "turn-terminal-agent",
            protocol::AgentTurnStatus::Succeeded,
        )
        .await;
        assert_eq!(agent.model_steps, 3);
        assert_eq!(agent.tool_calls, 2);
        assert_eq!(agent.calls.len(), 2);
        assert_eq!(agent.calls[0].tool, TEST_TERMINAL_OPEN_TOOL_NAME);
        assert_eq!(agent.calls[1].tool, TEST_TERMINAL_SEND_TOOL_NAME);
        for call in &agent.calls {
            assert!(call.approval_required);
            assert_eq!(call.status, AgentToolCallStatus::Succeeded);
        }
        assert_eq!(
            agent.calls[0].output,
            Some(serde_json::json!({
                "session_id": "pty-1",
                "name": "zeus-core",
                "backend_type": "test-isolated",
                "status": { "kind": "running" },
            }))
        );
        assert_eq!(
            agent.calls[1].output,
            Some(serde_json::json!({
                "viewport": "zeus ready\n",
                "wait_reason": "inferred_idle",
                "status": { "kind": "running" },
                "truncated": false,
            }))
        );
        let actions = backend_actions.lock().unwrap().clone();
        assert_eq!(actions.len(), 3);
        assert_eq!(
            actions[1],
            RecordedTerminalAction::Send {
                session_id: "pty-1".into(),
                request: TerminalSendRequest {
                    text: "echo zeus".into(),
                    submit: true,
                },
            }
        );
        assert_eq!(
            actions[2],
            RecordedTerminalAction::Close {
                session_id: "pty-1".into(),
            }
        );

        let recorded = requests.lock().unwrap().clone();
        assert_eq!(recorded.len(), 3);
        for (request_index, call_index) in [(1, 0), (2, 1)] {
            let tool_result = recorded[request_index].messages.last().unwrap();
            assert_eq!(tool_result.role, ReplyRole::Tool);
            assert_eq!(
                serde_json::from_str::<serde_json::Value>(&tool_result.content).unwrap(),
                agent.calls[call_index].output.clone().unwrap()
            );
        }

        drop(app);
        drop(store);
        tokio::task::yield_now().await;
        cleanup_test_database(&path);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[tokio::test]
    async fn terminal_send_deadline_settles_outcome_unknown_without_retry() {
        let unique = UserId::generate().unwrap();
        let root = std::env::temp_dir().join(format!(
            "zeus-api-terminal-unknown-{}",
            unique.as_str().replace(':', "-")
        ));
        let path = root.join("zeus.db");
        let marker_root = root.join("markers");
        std::fs::create_dir_all(&root).unwrap();
        let backend_actions = Arc::new(StdMutex::new(Vec::new()));
        let terminal_service = Arc::new(
            TerminalService::with_deadlines(
                [Arc::new(RecordingTerminalBackend {
                    actions: Arc::clone(&backend_actions),
                    hang_send: true,
                }) as Arc<dyn TerminalBackend>],
                TerminalDeadlines::new(
                    Duration::from_millis(100),
                    Duration::from_millis(25),
                    Duration::from_millis(100),
                    Duration::from_millis(100),
                )
                .unwrap(),
            )
            .unwrap(),
        );
        let store = DemoStore::open_local_with_terminal(&path, &marker_root, terminal_service)
            .await
            .unwrap();
        let owner =
            provision_test_owner(&store, "user-terminal-unknown", "terminal-unknown-owner").await;
        store
            .create_session_for_actor(
                &owner.authz,
                CreateSessionRequest {
                    id: "session-terminal-unknown".into(),
                    title: "Unknown terminal outcome".into(),
                },
                "create-terminal-unknown",
            )
            .await
            .unwrap();
        let requests = Arc::new(StdMutex::new(Vec::new()));
        let app = authenticated_app_with_provider(
            store.clone(),
            false,
            Arc::new(TerminalOpenSendThenFinalProvider::new(Arc::clone(
                &requests,
            ))),
        )
        .unwrap();

        let started = app
            .clone()
            .oneshot(
                Request::post("/api/v1/sessions/session-terminal-unknown/turns")
                    .header(header::HOST, "zeus.test")
                    .header(header::ORIGIN, "http://zeus.test")
                    .header(header::COOKIE, &owner.cookie_header)
                    .header(CSRF_HEADER, &owner.csrf_token)
                    .header(header::CONTENT_TYPE, "application/json")
                    .header("idempotency-key", "start-terminal-unknown")
                    .body(Body::from(
                        serde_json::json!({
                            "turn_id": "turn-terminal-unknown",
                            "user_message": "run the command whose terminal result becomes indeterminate",
                            "expected_sequence": 1,
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(started.status(), StatusCode::ACCEPTED);

        let waiting_open = wait_for_agent_status(
            &store,
            &owner.authz,
            "session-terminal-unknown",
            "turn-terminal-unknown",
            protocol::AgentTurnStatus::WaitingApproval,
        )
        .await;
        approve_agent_tool(
            &app,
            &owner,
            "session-terminal-unknown",
            "turn-terminal-unknown",
            waiting_open.pending_call_id.as_deref().unwrap(),
            "approve-terminal-unknown-open",
        )
        .await;

        let waiting_send = wait_for_agent_status(
            &store,
            &owner.authz,
            "session-terminal-unknown",
            "turn-terminal-unknown",
            protocol::AgentTurnStatus::WaitingApproval,
        )
        .await;
        assert_eq!(waiting_send.calls.len(), 2);
        assert_eq!(waiting_send.calls[1].tool, TEST_TERMINAL_SEND_TOOL_NAME);
        approve_agent_tool(
            &app,
            &owner,
            "session-terminal-unknown",
            "turn-terminal-unknown",
            waiting_send.pending_call_id.as_deref().unwrap(),
            "approve-terminal-unknown-send",
        )
        .await;

        let agent = wait_for_agent_status(
            &store,
            &owner.authz,
            "session-terminal-unknown",
            "turn-terminal-unknown",
            protocol::AgentTurnStatus::NeedsAttention,
        )
        .await;
        assert_eq!(agent.model_steps, 2);
        assert_eq!(agent.tool_calls, 2);
        assert_eq!(agent.calls[0].status, AgentToolCallStatus::Succeeded);
        assert_eq!(agent.calls[1].status, AgentToolCallStatus::OutcomeUnknown);
        assert_eq!(
            agent.calls[1]
                .error
                .as_ref()
                .and_then(|error| error.get("code"))
                .and_then(serde_json::Value::as_str),
            Some("executor_outcome_unknown")
        );
        assert_eq!(
            agent
                .last_error
                .as_ref()
                .and_then(|error| error.get("code"))
                .and_then(serde_json::Value::as_str),
            Some("executor_outcome_unknown")
        );
        assert_eq!(backend_actions.lock().unwrap().len(), 3);
        assert_eq!(requests.lock().unwrap().len(), 2);
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(backend_actions.lock().unwrap().len(), 3);
        assert_eq!(requests.lock().unwrap().len(), 2);

        drop(app);
        drop(store);
        tokio::task::yield_now().await;
        cleanup_test_database(&path);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[tokio::test]
    async fn read_only_workspace_search_and_line_read_execute_without_approval_and_replay_exactly()
    {
        let _workspace_test_guard = WORKSPACE_DISCOVERY_AGENT_TEST_LOCK.lock().await;
        let unique = UserId::generate().unwrap();
        let root = std::env::temp_dir().join(format!(
            "zeus-api-workspace-read-{}",
            unique.as_str().replace(':', "-")
        ));
        let path = root.join("zeus.db");
        let marker_root = root.join("markers");
        let workspace_root = root.join("workspace");
        std::fs::create_dir_all(workspace_root.join("src")).unwrap();
        std::fs::write(
            workspace_root.join("src/lib.rs"),
            "pub fn governed_workspace() {}\n",
        )
        .unwrap();
        let store = DemoStore::open_local_with_workspace(&path, &marker_root, &workspace_root)
            .await
            .unwrap();
        let owner = provision_test_owner(&store, "user-workspace-read", "workspace-owner").await;
        store
            .create_session_for_actor(
                &owner.authz,
                CreateSessionRequest {
                    id: "session-workspace-read".into(),
                    title: "Read workspace".into(),
                },
                "create-workspace-read",
            )
            .await
            .unwrap();
        let requests = Arc::new(StdMutex::new(Vec::new()));
        let app = authenticated_app_with_provider(
            store.clone(),
            false,
            Arc::new(WorkspaceSearchThenFinalProvider::new(Arc::clone(&requests))),
        )
        .unwrap();

        let started = app
            .clone()
            .oneshot(
                Request::post("/api/v1/sessions/session-workspace-read/turns")
                    .header(header::HOST, "zeus.test")
                    .header(header::ORIGIN, "http://zeus.test")
                    .header(header::COOKIE, &owner.cookie_header)
                    .header(CSRF_HEADER, &owner.csrf_token)
                    .header(header::CONTENT_TYPE, "application/json")
                    .header("idempotency-key", "start-workspace-read")
                    .body(Body::from(
                        serde_json::json!({
                            "turn_id": "turn-workspace-read",
                            "user_message": "find and read the governed workspace function",
                            "expected_sequence": 1,
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(started.status(), StatusCode::ACCEPTED);

        let session = wait_for_ready_session(&store, &owner.authz, "session-workspace-read").await;
        assert_eq!(
            session.turns[0].assistant_message.as_deref(),
            Some("workspace read completed")
        );
        let agent = wait_for_agent_status(
            &store,
            &owner.authz,
            "session-workspace-read",
            "turn-workspace-read",
            protocol::AgentTurnStatus::Succeeded,
        )
        .await;
        assert_eq!(agent.model_steps, 3);
        assert_eq!(agent.tool_calls, 2);
        assert_eq!(agent.calls.len(), 2);
        assert_eq!(agent.calls[0].tool, TEST_WORKSPACE_SEARCH_TEXT_TOOL_NAME);
        assert_eq!(
            agent.calls[0].output,
            Some(serde_json::json!({
                "path": ".",
                "query": "governed_workspace",
                "matches": [{
                    "path": "src/lib.rs",
                    "line": 1,
                    "text": "pub fn governed_workspace() {}",
                }],
                "truncated": false,
                "scanned_directories": 2,
                "scanned_files": 1,
                "scanned_bytes": 31,
                "skipped_entries": 0,
            }))
        );
        assert_eq!(agent.calls[1].tool, TEST_WORKSPACE_READ_LINES_TOOL_NAME);
        for call in &agent.calls {
            assert!(!call.approval_required);
            assert!(call.review.is_none());
            assert_eq!(call.status, AgentToolCallStatus::Succeeded);
        }
        assert_eq!(
            agent.calls[1].output,
            Some(serde_json::json!({
                "path": "src/lib.rs",
                "start_line": 1,
                "end_line": 1,
                "total_lines": 2,
                "content": "pub fn governed_workspace() {}\n",
                "bytes": 31,
            }))
        );
        assert_eq!(std::fs::read_dir(&marker_root).unwrap().count(), 0);

        let recorded = requests.lock().unwrap().clone();
        assert_eq!(recorded.len(), 3);
        let search_result = recorded[1].messages.last().unwrap();
        assert_eq!(search_result.role, ReplyRole::Tool);
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&search_result.content).unwrap(),
            agent.calls[0].output.clone().unwrap()
        );
        let line_result = recorded[2].messages.last().unwrap();
        assert_eq!(line_result.role, ReplyRole::Tool);
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&line_result.content).unwrap(),
            agent.calls[1].output.clone().unwrap()
        );

        drop(app);
        drop(store);
        tokio::task::yield_now().await;
        cleanup_test_database(&path);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[tokio::test]
    async fn read_only_workspace_find_and_line_read_execute_without_approval_and_replay_exactly() {
        let _workspace_test_guard = WORKSPACE_DISCOVERY_AGENT_TEST_LOCK.lock().await;
        let unique = UserId::generate().unwrap();
        let root = std::env::temp_dir().join(format!(
            "zeus-api-workspace-find-{}",
            unique.as_str().replace(':', "-")
        ));
        let path = root.join("zeus.db");
        let marker_root = root.join("markers");
        let workspace_root = root.join("workspace");
        std::fs::create_dir_all(workspace_root.join("src")).unwrap();
        std::fs::write(workspace_root.join("src/lib.rs"), "pub fn zeus() {}\n").unwrap();
        let store = DemoStore::open_local_with_workspace(&path, &marker_root, &workspace_root)
            .await
            .unwrap();
        let owner =
            provision_test_owner(&store, "user-workspace-find", "workspace-find-owner").await;
        store
            .create_session_for_actor(
                &owner.authz,
                CreateSessionRequest {
                    id: "session-workspace-find".into(),
                    title: "Find workspace path".into(),
                },
                "create-workspace-find",
            )
            .await
            .unwrap();
        let requests = Arc::new(StdMutex::new(Vec::new()));
        let app = authenticated_app_with_provider(
            store.clone(),
            false,
            Arc::new(WorkspaceFindThenFinalProvider::new(Arc::clone(&requests))),
        )
        .unwrap();

        let started = app
            .clone()
            .oneshot(
                Request::post("/api/v1/sessions/session-workspace-find/turns")
                    .header(header::HOST, "zeus.test")
                    .header(header::ORIGIN, "http://zeus.test")
                    .header(header::COOKIE, &owner.cookie_header)
                    .header(CSRF_HEADER, &owner.csrf_token)
                    .header(header::CONTENT_TYPE, "application/json")
                    .header("idempotency-key", "start-workspace-find")
                    .body(Body::from(
                        serde_json::json!({
                            "turn_id": "turn-workspace-find",
                            "user_message": "find a Rust source file and read its first line",
                            "expected_sequence": 1,
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(started.status(), StatusCode::ACCEPTED);

        let session = wait_for_ready_session(&store, &owner.authz, "session-workspace-find").await;
        assert_eq!(
            session.turns[0].assistant_message.as_deref(),
            Some("workspace path discovery completed")
        );
        let agent = wait_for_agent_status(
            &store,
            &owner.authz,
            "session-workspace-find",
            "turn-workspace-find",
            protocol::AgentTurnStatus::Succeeded,
        )
        .await;
        assert_eq!(agent.model_steps, 3);
        assert_eq!(agent.tool_calls, 2);
        assert_eq!(agent.calls.len(), 2);
        assert_eq!(agent.calls[0].tool, TEST_WORKSPACE_FIND_PATHS_TOOL_NAME);
        assert_eq!(
            agent.calls[0].output,
            Some(serde_json::json!({
                "path": ".",
                "pattern": "**/*.rs",
                "matches": ["src/lib.rs"],
                "truncated": false,
                "scanned_directories": 2,
                "scanned_files": 1,
                "scanned_entries": 2,
                "skipped_entries": 0,
            }))
        );
        assert_eq!(agent.calls[1].tool, TEST_WORKSPACE_READ_LINES_TOOL_NAME);
        assert_eq!(
            agent.calls[1].output,
            Some(serde_json::json!({
                "path": "src/lib.rs",
                "start_line": 1,
                "end_line": 1,
                "total_lines": 2,
                "content": "pub fn zeus() {}\n",
                "bytes": 17,
            }))
        );
        for call in &agent.calls {
            assert!(!call.approval_required);
            assert!(call.review.is_none());
            assert_eq!(call.status, AgentToolCallStatus::Succeeded);
        }
        assert_eq!(std::fs::read_dir(&marker_root).unwrap().count(), 0);

        let recorded = requests.lock().unwrap().clone();
        assert_eq!(recorded.len(), 3);
        for (request_index, call_index) in [(1, 0), (2, 1)] {
            let tool_result = recorded[request_index].messages.last().unwrap();
            assert_eq!(tool_result.role, ReplyRole::Tool);
            assert_eq!(
                serde_json::from_str::<serde_json::Value>(&tool_result.content).unwrap(),
                agent.calls[call_index].output.clone().unwrap()
            );
        }

        drop(app);
        drop(store);
        tokio::task::yield_now().await;
        cleanup_test_database(&path);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[tokio::test]
    async fn workspace_replace_waits_for_owner_approval_then_replays_the_exact_result() {
        let unique = UserId::generate().unwrap();
        let root = std::env::temp_dir().join(format!(
            "zeus-api-workspace-replace-{}",
            unique.as_str().replace(':', "-")
        ));
        let path = root.join("zeus.db");
        let marker_root = root.join("markers");
        let workspace_root = root.join("workspace");
        let target = workspace_root.join("src/lib.rs");
        std::fs::create_dir_all(target.parent().unwrap()).unwrap();
        std::fs::write(&target, "pub fn before() {}\n").unwrap();
        let store = DemoStore::open_local_with_workspace(&path, &marker_root, &workspace_root)
            .await
            .unwrap();
        let owner =
            provision_test_owner(&store, "user-workspace-replace", "workspace-replace-owner").await;
        store
            .create_session_for_actor(
                &owner.authz,
                CreateSessionRequest {
                    id: "session-workspace-replace".into(),
                    title: "Edit workspace".into(),
                },
                "create-workspace-replace",
            )
            .await
            .unwrap();
        let requests = Arc::new(StdMutex::new(Vec::new()));
        let app = authenticated_app_with_provider(
            store.clone(),
            false,
            Arc::new(WorkspaceReplaceThenFinalProvider::new(Arc::clone(
                &requests,
            ))),
        )
        .unwrap();

        let started = app
            .clone()
            .oneshot(
                Request::post("/api/v1/sessions/session-workspace-replace/turns")
                    .header(header::HOST, "zeus.test")
                    .header(header::ORIGIN, "http://zeus.test")
                    .header(header::COOKIE, &owner.cookie_header)
                    .header(CSRF_HEADER, &owner.csrf_token)
                    .header(header::CONTENT_TYPE, "application/json")
                    .header("idempotency-key", "start-workspace-replace")
                    .body(Body::from(
                        serde_json::json!({
                            "turn_id": "turn-workspace-replace",
                            "user_message": "rename the function from before to after",
                            "expected_sequence": 1,
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(started.status(), StatusCode::ACCEPTED);

        let waiting = wait_for_agent_status(
            &store,
            &owner.authz,
            "session-workspace-replace",
            "turn-workspace-replace",
            protocol::AgentTurnStatus::WaitingApproval,
        )
        .await;
        let call_id = waiting.pending_call_id.clone().unwrap();
        assert_eq!(waiting.calls.len(), 1);
        assert_eq!(waiting.calls[0].tool, TEST_WORKSPACE_REPLACE_TEXT_TOOL_NAME);
        assert!(waiting.calls[0].approval_required);
        assert_eq!(
            waiting.calls[0].status,
            AgentToolCallStatus::WaitingApproval
        );
        assert_eq!(
            std::fs::read_to_string(&target).unwrap(),
            "pub fn before() {}\n"
        );

        let approved = app
            .clone()
            .oneshot(
                Request::post(format!(
                    "/api/v1/sessions/session-workspace-replace/turns/turn-workspace-replace/approvals/{call_id}/decision"
                ))
                .header(header::HOST, "zeus.test")
                .header(header::ORIGIN, "http://zeus.test")
                .header(header::COOKIE, &owner.cookie_header)
                .header(CSRF_HEADER, &owner.csrf_token)
                .header(header::CONTENT_TYPE, "application/json")
                .header("idempotency-key", "approve-workspace-replace")
                .body(Body::from(
                    serde_json::json!({
                        "decision": "approve",
                        "note": "apply the exact unique replacement",
                        "idempotency_key": "approve-workspace-replace",
                    })
                    .to_string(),
                ))
                .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(approved.status(), StatusCode::OK);

        let session =
            wait_for_ready_session(&store, &owner.authz, "session-workspace-replace").await;
        assert_eq!(
            session.turns[0].assistant_message.as_deref(),
            Some("workspace edit completed")
        );
        let agent = wait_for_agent_status(
            &store,
            &owner.authz,
            "session-workspace-replace",
            "turn-workspace-replace",
            protocol::AgentTurnStatus::Succeeded,
        )
        .await;
        assert_eq!(agent.model_steps, 2);
        assert_eq!(agent.tool_calls, 1);
        assert_eq!(agent.calls.len(), 1);
        assert_eq!(agent.calls[0].status, AgentToolCallStatus::Succeeded);
        assert_eq!(
            agent.calls[0].output,
            Some(serde_json::json!({
                "path": "src/lib.rs",
                "replacements": 1,
                "bytes_before": 19,
                "bytes_after": 18,
            }))
        );
        assert_eq!(
            std::fs::read_to_string(&target).unwrap(),
            "pub fn after() {}\n"
        );
        assert_eq!(std::fs::read_dir(&marker_root).unwrap().count(), 0);

        let recorded = requests.lock().unwrap().clone();
        assert_eq!(recorded.len(), 2);
        let tool_result = recorded[1].messages.last().unwrap();
        assert_eq!(tool_result.role, ReplyRole::Tool);
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&tool_result.content).unwrap(),
            agent.calls[0].output.clone().unwrap()
        );

        drop(app);
        drop(store);
        tokio::task::yield_now().await;
        cleanup_test_database(&path);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[tokio::test]
    async fn workspace_create_waits_for_owner_approval_then_replays_the_exact_result() {
        let unique = UserId::generate().unwrap();
        let root = std::env::temp_dir().join(format!(
            "zeus-api-workspace-create-{}",
            unique.as_str().replace(':', "-")
        ));
        let path = root.join("zeus.db");
        let marker_root = root.join("markers");
        let workspace_root = root.join("workspace");
        let target = workspace_root.join("src/generated.rs");
        std::fs::create_dir_all(target.parent().unwrap()).unwrap();
        let store = DemoStore::open_local_with_workspace(&path, &marker_root, &workspace_root)
            .await
            .unwrap();
        let owner =
            provision_test_owner(&store, "user-workspace-create", "workspace-create-owner").await;
        store
            .create_session_for_actor(
                &owner.authz,
                CreateSessionRequest {
                    id: "session-workspace-create".into(),
                    title: "Create workspace file".into(),
                },
                "create-workspace-create",
            )
            .await
            .unwrap();
        let requests = Arc::new(StdMutex::new(Vec::new()));
        let app = authenticated_app_with_provider(
            store.clone(),
            false,
            Arc::new(WorkspaceCreateThenFinalProvider::new(Arc::clone(&requests))),
        )
        .unwrap();

        let started = app
            .clone()
            .oneshot(
                Request::post("/api/v1/sessions/session-workspace-create/turns")
                    .header(header::HOST, "zeus.test")
                    .header(header::ORIGIN, "http://zeus.test")
                    .header(header::COOKIE, &owner.cookie_header)
                    .header(CSRF_HEADER, &owner.csrf_token)
                    .header(header::CONTENT_TYPE, "application/json")
                    .header("idempotency-key", "start-workspace-create")
                    .body(Body::from(
                        serde_json::json!({
                            "turn_id": "turn-workspace-create",
                            "user_message": "create a generated Rust source file",
                            "expected_sequence": 1,
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(started.status(), StatusCode::ACCEPTED);

        let waiting = wait_for_agent_status(
            &store,
            &owner.authz,
            "session-workspace-create",
            "turn-workspace-create",
            protocol::AgentTurnStatus::WaitingApproval,
        )
        .await;
        let call_id = waiting.pending_call_id.clone().unwrap();
        assert_eq!(waiting.calls.len(), 1);
        assert_eq!(waiting.calls[0].tool, TEST_WORKSPACE_CREATE_FILE_TOOL_NAME);
        assert!(waiting.calls[0].approval_required);
        assert_eq!(
            waiting.calls[0].status,
            AgentToolCallStatus::WaitingApproval
        );
        assert!(!target.exists());

        let approved = app
            .clone()
            .oneshot(
                Request::post(format!(
                    "/api/v1/sessions/session-workspace-create/turns/turn-workspace-create/approvals/{call_id}/decision"
                ))
                .header(header::HOST, "zeus.test")
                .header(header::ORIGIN, "http://zeus.test")
                .header(header::COOKIE, &owner.cookie_header)
                .header(CSRF_HEADER, &owner.csrf_token)
                .header(header::CONTENT_TYPE, "application/json")
                .header("idempotency-key", "approve-workspace-create")
                .body(Body::from(
                    serde_json::json!({
                        "decision": "approve",
                        "note": "create this exact new file",
                        "idempotency_key": "approve-workspace-create",
                    })
                    .to_string(),
                ))
                .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(approved.status(), StatusCode::OK);

        let session =
            wait_for_ready_session(&store, &owner.authz, "session-workspace-create").await;
        assert_eq!(
            session.turns[0].assistant_message.as_deref(),
            Some("workspace file created")
        );
        let agent = wait_for_agent_status(
            &store,
            &owner.authz,
            "session-workspace-create",
            "turn-workspace-create",
            protocol::AgentTurnStatus::Succeeded,
        )
        .await;
        assert_eq!(agent.model_steps, 2);
        assert_eq!(agent.tool_calls, 1);
        assert_eq!(agent.calls.len(), 1);
        assert_eq!(agent.calls[0].status, AgentToolCallStatus::Succeeded);
        assert_eq!(
            agent.calls[0].output,
            Some(serde_json::json!({
                "path": "src/generated.rs",
                "bytes": 22,
                "created": true,
            }))
        );
        assert_eq!(
            std::fs::read_to_string(&target).unwrap(),
            "pub fn generated() {}\n"
        );
        assert_eq!(std::fs::read_dir(&marker_root).unwrap().count(), 0);

        let recorded = requests.lock().unwrap().clone();
        assert_eq!(recorded.len(), 2);
        let tool_result = recorded[1].messages.last().unwrap();
        assert_eq!(tool_result.role, ReplyRole::Tool);
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&tool_result.content).unwrap(),
            agent.calls[0].output.clone().unwrap()
        );

        drop(app);
        drop(store);
        tokio::task::yield_now().await;
        cleanup_test_database(&path);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[tokio::test]
    async fn workspace_insert_waits_for_owner_approval_then_replays_the_exact_result() {
        let unique = UserId::generate().unwrap();
        let root = std::env::temp_dir().join(format!(
            "zeus-api-workspace-insert-{}",
            unique.as_str().replace(':', "-")
        ));
        let path = root.join("zeus.db");
        let marker_root = root.join("markers");
        let workspace_root = root.join("workspace");
        let target = workspace_root.join("src/lib.rs");
        std::fs::create_dir_all(target.parent().unwrap()).unwrap();
        std::fs::write(&target, "one\ntwo\n").unwrap();
        let store = DemoStore::open_local_with_workspace(&path, &marker_root, &workspace_root)
            .await
            .unwrap();
        let owner =
            provision_test_owner(&store, "user-workspace-insert", "workspace-insert-owner").await;
        store
            .create_session_for_actor(
                &owner.authz,
                CreateSessionRequest {
                    id: "session-workspace-insert".into(),
                    title: "Insert workspace text".into(),
                },
                "create-workspace-insert",
            )
            .await
            .unwrap();
        let requests = Arc::new(StdMutex::new(Vec::new()));
        let app = authenticated_app_with_provider(
            store.clone(),
            false,
            Arc::new(WorkspaceInsertThenFinalProvider::new(Arc::clone(&requests))),
        )
        .unwrap();

        let started = app
            .clone()
            .oneshot(
                Request::post("/api/v1/sessions/session-workspace-insert/turns")
                    .header(header::HOST, "zeus.test")
                    .header(header::ORIGIN, "http://zeus.test")
                    .header(header::COOKIE, &owner.cookie_header)
                    .header(CSRF_HEADER, &owner.csrf_token)
                    .header(header::CONTENT_TYPE, "application/json")
                    .header("idempotency-key", "start-workspace-insert")
                    .body(Body::from(
                        serde_json::json!({
                            "turn_id": "turn-workspace-insert",
                            "user_message": "insert a line between one and two",
                            "expected_sequence": 1,
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(started.status(), StatusCode::ACCEPTED);

        let waiting = wait_for_agent_status(
            &store,
            &owner.authz,
            "session-workspace-insert",
            "turn-workspace-insert",
            protocol::AgentTurnStatus::WaitingApproval,
        )
        .await;
        let call_id = waiting.pending_call_id.clone().unwrap();
        assert_eq!(waiting.calls.len(), 1);
        assert_eq!(waiting.calls[0].tool, TEST_WORKSPACE_INSERT_TEXT_TOOL_NAME);
        assert!(waiting.calls[0].approval_required);
        assert_eq!(
            waiting.calls[0].status,
            AgentToolCallStatus::WaitingApproval
        );
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "one\ntwo\n");

        let approved = app
            .clone()
            .oneshot(
                Request::post(format!(
                    "/api/v1/sessions/session-workspace-insert/turns/turn-workspace-insert/approvals/{call_id}/decision"
                ))
                .header(header::HOST, "zeus.test")
                .header(header::ORIGIN, "http://zeus.test")
                .header(header::COOKIE, &owner.cookie_header)
                .header(CSRF_HEADER, &owner.csrf_token)
                .header(header::CONTENT_TYPE, "application/json")
                .header("idempotency-key", "approve-workspace-insert")
                .body(Body::from(
                    serde_json::json!({
                        "decision": "approve",
                        "note": "insert this exact text at the approved line boundary",
                        "idempotency_key": "approve-workspace-insert",
                    })
                    .to_string(),
                ))
                .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(approved.status(), StatusCode::OK);

        let session =
            wait_for_ready_session(&store, &owner.authz, "session-workspace-insert").await;
        assert_eq!(
            session.turns[0].assistant_message.as_deref(),
            Some("workspace text inserted")
        );
        let agent = wait_for_agent_status(
            &store,
            &owner.authz,
            "session-workspace-insert",
            "turn-workspace-insert",
            protocol::AgentTurnStatus::Succeeded,
        )
        .await;
        assert_eq!(agent.model_steps, 2);
        assert_eq!(agent.tool_calls, 1);
        assert_eq!(agent.calls.len(), 1);
        assert_eq!(agent.calls[0].status, AgentToolCallStatus::Succeeded);
        assert_eq!(
            agent.calls[0].output,
            Some(serde_json::json!({
                "path": "src/lib.rs",
                "after_line": 1,
                "inserted_lines": 1,
                "bytes_before": 8,
                "bytes_after": 16,
            }))
        );
        assert_eq!(
            std::fs::read_to_string(&target).unwrap(),
            "one\nbetween\ntwo\n"
        );
        assert_eq!(std::fs::read_dir(&marker_root).unwrap().count(), 0);

        let recorded = requests.lock().unwrap().clone();
        assert_eq!(recorded.len(), 2);
        let tool_result = recorded[1].messages.last().unwrap();
        assert_eq!(tool_result.role, ReplyRole::Tool);
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&tool_result.content).unwrap(),
            agent.calls[0].output.clone().unwrap()
        );

        drop(app);
        drop(store);
        tokio::task::yield_now().await;
        cleanup_test_database(&path);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[tokio::test]
    async fn agent_tool_rejection_uses_exact_result_and_replays_after_final() {
        let unique = UserId::generate().unwrap();
        let root = std::env::temp_dir().join(format!(
            "zeus-api-agent-reject-{}",
            unique.as_str().replace(':', "-")
        ));
        let path = root.join("zeus.db");
        let marker_root = root.join("markers");
        std::fs::create_dir_all(&root).unwrap();
        let store = DemoStore::open_local(&path, &marker_root).await.unwrap();
        let owner = provision_test_owner(&store, "user-agent-reject", "agent-reject-owner").await;
        store
            .create_session_for_actor(
                &owner.authz,
                CreateSessionRequest {
                    id: "session-agent-reject".into(),
                    title: "Rejected Agent tool".into(),
                },
                "create-agent-reject",
            )
            .await
            .unwrap();
        let requests = Arc::new(StdMutex::new(Vec::new()));
        let app = authenticated_app_with_provider(
            store.clone(),
            false,
            Arc::new(ToolThenFinalProvider::new(Arc::clone(&requests))),
        )
        .unwrap();

        let started = app
            .clone()
            .oneshot(
                Request::post("/api/v1/sessions/session-agent-reject/turns")
                    .header(header::HOST, "zeus.test")
                    .header(header::ORIGIN, "http://zeus.test")
                    .header(header::COOKIE, &owner.cookie_header)
                    .header(CSRF_HEADER, &owner.csrf_token)
                    .header(header::CONTENT_TYPE, "application/json")
                    .header("idempotency-key", "start-agent-reject")
                    .body(Body::from(
                        serde_json::json!({
                            "turn_id": "turn-agent-reject",
                            "user_message": "propose a marker I will reject",
                            "expected_sequence": 1,
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(started.status(), StatusCode::ACCEPTED);
        let waiting = wait_for_agent_status(
            &store,
            &owner.authz,
            "session-agent-reject",
            "turn-agent-reject",
            protocol::AgentTurnStatus::WaitingApproval,
        )
        .await;
        let call_id = waiting.pending_call_id.unwrap();
        let rejection = || {
            Request::post(format!(
                "/api/v1/sessions/session-agent-reject/turns/turn-agent-reject/approvals/{call_id}/decision"
            ))
            .header(header::HOST, "zeus.test")
            .header(header::ORIGIN, "http://zeus.test")
            .header(header::COOKIE, &owner.cookie_header)
            .header(CSRF_HEADER, &owner.csrf_token)
            .header(header::CONTENT_TYPE, "application/json")
            .header("idempotency-key", "reject-agent-tool")
            .body(Body::from(
                serde_json::json!({
                    "decision": "reject",
                    "note": "not authorized for this turn",
                    "idempotency_key": "reject-agent-tool",
                })
                .to_string(),
            ))
            .unwrap()
        };

        let rejected = app.clone().oneshot(rejection()).await.unwrap();
        assert_eq!(rejected.status(), StatusCode::OK);
        let rejected: AgentReviewResponse = response_json(rejected).await;
        assert!(!rejected.replayed);
        assert_eq!(rejected.call.status, AgentToolCallStatus::Rejected);
        assert_eq!(std::fs::read_dir(&marker_root).unwrap().count(), 0);

        wait_for_ready_session(&store, &owner.authz, "session-agent-reject").await;
        let agent = wait_for_agent_status(
            &store,
            &owner.authz,
            "session-agent-reject",
            "turn-agent-reject",
            protocol::AgentTurnStatus::Succeeded,
        )
        .await;
        assert_eq!(agent.model_steps, 2);
        assert_eq!(agent.tool_calls, 1);
        assert_eq!(agent.calls[0].status, AgentToolCallStatus::Rejected);
        let expected_result = protocol::agent_approval_rejected_result(
            &call_id,
            Some("not authorized for this turn"),
        );
        assert_eq!(agent.calls[0].error.as_ref(), Some(&expected_result));
        assert_eq!(std::fs::read_dir(&marker_root).unwrap().count(), 0);

        let recorded = requests.lock().unwrap().clone();
        assert_eq!(recorded.len(), 2);
        assert_eq!(recorded[1].messages.len(), 5);
        assert_eq!(recorded[1].messages[0], recorded[0].messages[0]);
        assert_eq!(recorded[1].messages[0].role, ReplyRole::System);
        assert_eq!(recorded[1].messages[1], recorded[0].messages[1]);
        assert_eq!(recorded[1].messages[2], recorded[0].messages[2]);
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&recorded[1].messages[4].content).unwrap(),
            expected_result
        );
        assert_eq!(
            recorded[1].messages[4].tool_call_id.as_deref(),
            Some("provider-call-approved-1")
        );

        let replay = app.clone().oneshot(rejection()).await.unwrap();
        assert_eq!(replay.status(), StatusCode::OK);
        let replay: AgentReviewResponse = response_json(replay).await;
        assert!(replay.replayed);
        assert_eq!(replay.call.status, AgentToolCallStatus::Rejected);
        assert_eq!(requests.lock().unwrap().len(), 2);
        assert_eq!(std::fs::read_dir(&marker_root).unwrap().count(), 0);

        drop(app);
        drop(store);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[tokio::test]
    async fn agent_history_is_trimmed_to_reserved_budget_before_tool_to_final() {
        let unique = UserId::generate().unwrap();
        let root = std::env::temp_dir().join(format!(
            "zeus-api-agent-history-{}",
            unique.as_str().replace(':', "-")
        ));
        let path = root.join("zeus.db");
        let marker_root = root.join("markers");
        std::fs::create_dir_all(&root).unwrap();
        let store = DemoStore::open_local(&path, &marker_root).await.unwrap();
        let owner = provision_test_owner(&store, "user-agent-history", "agent-history-owner").await;
        store
            .create_session_for_actor(
                &owner.authz,
                CreateSessionRequest {
                    id: "session-agent-history".into(),
                    title: "Bounded Agent history".into(),
                },
                "create-agent-history",
            )
            .await
            .unwrap();
        let requests = Arc::new(StdMutex::new(Vec::new()));
        let app = authenticated_app_with_provider(
            store.clone(),
            false,
            Arc::new(HistoryThenToolProvider::new(Arc::clone(&requests))),
        )
        .unwrap();
        let send_turn =
            |turn_id: &str, user_message: String, expected_sequence: u64, idempotency_key: &str| {
                Request::post("/api/v1/sessions/session-agent-history/turns")
                    .header(header::HOST, "zeus.test")
                    .header(header::ORIGIN, "http://zeus.test")
                    .header(header::COOKIE, &owner.cookie_header)
                    .header(CSRF_HEADER, &owner.csrf_token)
                    .header(header::CONTENT_TYPE, "application/json")
                    .header("idempotency-key", idempotency_key)
                    .body(Body::from(
                        serde_json::json!({
                            "turn_id": turn_id,
                            "user_message": user_message,
                            "expected_sequence": expected_sequence,
                        })
                        .to_string(),
                    ))
                    .unwrap()
            };

        let first = app
            .clone()
            .oneshot(send_turn(
                "turn-agent-history-1",
                "u".repeat(40_000),
                1,
                "agent-history-1",
            ))
            .await
            .unwrap();
        assert_eq!(first.status(), StatusCode::ACCEPTED);
        let after_first =
            wait_for_ready_session(&store, &owner.authz, "session-agent-history").await;

        let second = app
            .clone()
            .oneshot(send_turn(
                "turn-agent-history-2",
                "u".repeat(40_000),
                after_first.session.sequence,
                "agent-history-2",
            ))
            .await
            .unwrap();
        assert_eq!(second.status(), StatusCode::ACCEPTED);
        let after_second =
            wait_for_ready_session(&store, &owner.authz, "session-agent-history").await;

        let third = app
            .clone()
            .oneshot(send_turn(
                "turn-agent-history-3",
                "write after trimming".into(),
                after_second.session.sequence,
                "agent-history-3",
            ))
            .await
            .unwrap();
        assert_eq!(third.status(), StatusCode::ACCEPTED);
        let waiting = wait_for_agent_status(
            &store,
            &owner.authz,
            "session-agent-history",
            "turn-agent-history-3",
            protocol::AgentTurnStatus::WaitingApproval,
        )
        .await;
        let call_id = waiting.pending_call_id.unwrap();

        let approved = app
            .clone()
            .oneshot(
                Request::post(format!(
                    "/api/v1/sessions/session-agent-history/turns/turn-agent-history-3/approvals/{call_id}/decision"
                ))
                .header(header::HOST, "zeus.test")
                .header(header::ORIGIN, "http://zeus.test")
                .header(header::COOKIE, &owner.cookie_header)
                .header(CSRF_HEADER, &owner.csrf_token)
                .header(header::CONTENT_TYPE, "application/json")
                .header("idempotency-key", "approve-agent-history")
                .body(Body::from(
                    serde_json::json!({
                        "decision": "approve",
                        "note": null,
                    })
                    .to_string(),
                ))
                .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(approved.status(), StatusCode::OK);
        wait_for_ready_session(&store, &owner.authz, "session-agent-history").await;
        let agent = wait_for_agent_status(
            &store,
            &owner.authz,
            "session-agent-history",
            "turn-agent-history-3",
            protocol::AgentTurnStatus::Succeeded,
        )
        .await;
        assert_eq!(agent.model_steps, 2);
        assert_eq!(agent.calls[0].status, AgentToolCallStatus::Succeeded);
        assert_eq!(std::fs::read_dir(&marker_root).unwrap().count(), 1);

        let context = store
            .session_agent_knowledge_context(&owner.authz, "write after trimming")
            .await
            .unwrap()
            .snapshot
            .snapshot()
            .canonical_context()
            .to_owned();
        let recorded = requests.lock().unwrap();
        assert_eq!(recorded.len(), 4);
        assert_eq!(
            recorded[2].messages,
            vec![
                ReplyMessage::new(ReplyRole::System, store.session_agent_system_prompt(),),
                ReplyMessage::new(ReplyRole::User, "write after trimming"),
                ReplyMessage::new(ReplyRole::Context, context),
            ],
            "the 80 KiB newest pair must be omitted to preserve the 64 KiB Agent budget"
        );
        assert_eq!(recorded[3].messages.len(), 5);
        assert_eq!(recorded[3].messages[0], recorded[2].messages[0]);
        assert_eq!(recorded[3].messages[1], recorded[2].messages[1]);
        assert_eq!(recorded[3].messages[2], recorded[2].messages[2]);
        assert_eq!(recorded[3].messages[3].role, ReplyRole::Assistant);
        assert_eq!(recorded[3].messages[4].role, ReplyRole::Tool);
        drop(recorded);

        drop(app);
        drop(store);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[tokio::test]
    async fn legacy_oversized_session_path_accepts_a_new_bounded_turn() {
        let (app, store, owner, path) = authenticated_file_app("legacy-session-turn").await;
        let session_id = "s".repeat(protocol::SESSION_ID_MAX_BYTES + 1);
        insert_legacy_ready_session(&path, &session_id, &owner.user_id);

        let response = app
            .clone()
            .oneshot(
                Request::post(format!("/api/v1/sessions/{session_id}/turns"))
                    .header(header::HOST, "zeus.test")
                    .header(header::ORIGIN, "http://zeus.test")
                    .header(header::COOKIE, &owner.cookie_header)
                    .header(CSRF_HEADER, &owner.csrf_token)
                    .header(header::CONTENT_TYPE, "application/json")
                    .header("idempotency-key", "legacy-session-new-turn")
                    .body(Body::from(
                        serde_json::json!({
                            "turn_id": "turn-after-upgrade",
                            "user_message": "Continue this legacy Session safely",
                            "expected_sequence": 1,
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::ACCEPTED);

        let detail = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let detail = store
                    .get_session_for_actor(
                        &owner.authz,
                        &session_id,
                        None,
                        protocol::COLLECTION_PAGE_DEFAULT_LIMIT,
                        None,
                        protocol::COLLECTION_PAGE_DEFAULT_LIMIT,
                        None,
                        protocol::EVENT_PAGE_DEFAULT_LIMIT,
                    )
                    .await
                    .unwrap();
                if detail.session.status == SessionStatus::Ready {
                    break detail;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("the legacy Session reply should settle durably");
        assert_eq!(detail.turns.len(), 1);
        assert_eq!(detail.turns[0].id, "turn-after-upgrade");
        assert!(detail.events[0].id.len() > protocol::RESOURCE_ID_MAX_BYTES);
        assert!(
            detail.events[1..]
                .iter()
                .all(|event| event.id.len() <= protocol::RESOURCE_ID_MAX_BYTES)
        );

        drop(app);
        drop(store);
        cleanup_test_database(&path);
    }

    #[tokio::test]
    async fn legacy_oversized_reply_request_fails_durably_before_provider_execution() {
        let store = DemoStore::seeded().await.unwrap();
        let identity = provision_test_owner(&store, "user-owner", "owner").await;
        let session_id = "session-legacy-oversized-reply";
        let turn_id = "turn-legacy-oversized-reply";
        let job_id = "reply-legacy-oversized-reply";
        store
            .create_session_for_actor(
                &identity.authz,
                CreateSessionRequest {
                    id: session_id.into(),
                    title: "Legacy oversized reply".into(),
                },
                "create-legacy-oversized-reply",
            )
            .await
            .unwrap();

        let provider_calls = Arc::new(AtomicUsize::new(0));
        let provider: Arc<dyn ReplyProvider> =
            Arc::new(CountingProvider::new(Arc::clone(&provider_calls)));
        let metadata = provider.metadata().clone();
        store
            .start_turn_and_enqueue_reply_for_actor(
                &identity.authz,
                session_id,
                StartTurnRequest {
                    turn_id: turn_id.into(),
                    user_message: "valid legacy placeholder".into(),
                    expected_sequence: 1,
                },
                "start-legacy-oversized-reply",
                ReplyJobSpec {
                    id: job_id.into(),
                    authz: identity.authz.clone(),
                    provider_name: metadata.provider_id,
                    model_name: metadata.model,
                    request_json: serde_json::to_value(ReplyRequest::new([ReplyMessage::new(
                        ReplyRole::User,
                        "valid legacy placeholder",
                    )]))
                    .unwrap(),
                },
            )
            .await
            .unwrap();
        let ReplyClaimOutcome::Claimed(mut job) = store.claim_next_reply().await.unwrap() else {
            panic!("the legacy reply must be claimable");
        };
        job.request_json = serde_json::to_value(ReplyRequest::new([ReplyMessage::new(
            ReplyRole::User,
            "x".repeat(protocol::USER_MESSAGE_MAX_BYTES + 1),
        )]))
        .unwrap();
        let state = ApiState {
            store: store.clone(),
            durable_ledger_poll_interval: DURABLE_LEDGER_POLL_INTERVAL,
            broadcast_hints_enabled: false,
            auth: None,
            reply: Some(Arc::new(ReplyExecutor::new(provider))),
            sse_capacity: SseCapacity::production(),
        };

        process_reply_job(&state, *job).await.unwrap();

        assert_eq!(provider_calls.load(Ordering::Relaxed), 0);
        let stored = store
            .reply_job_for_actor(&identity.authz, job_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stored.status, runtime::ReplyJobStatus::Failed);
        assert_eq!(
            stored.error_json.unwrap()["code"],
            "persisted_request_exceeds_resource_envelope"
        );
        let detail = store
            .get_session_for_actor(
                &identity.authz,
                session_id,
                None,
                protocol::COLLECTION_PAGE_DEFAULT_LIMIT,
                None,
                protocol::COLLECTION_PAGE_DEFAULT_LIMIT,
                None,
                protocol::EVENT_PAGE_DEFAULT_LIMIT,
            )
            .await
            .unwrap();
        assert_eq!(detail.session.status, SessionStatus::NeedsAttention);
        assert!(matches!(
            &detail.events.last().unwrap().data,
            protocol::SessionEventData::TurnInterrupted { reason, .. }
                if reason == "assistant reply provider failed"
        ));
    }

    #[tokio::test]
    async fn oversized_custom_provider_reply_settles_once_as_a_bounded_failure() {
        let store = DemoStore::seeded().await.unwrap();
        let identity = provision_test_owner(&store, "user-owner", "owner").await;
        let session_id = "session-oversized-provider-reply";
        let turn_id = "turn-oversized-provider-reply";
        let job_id = "reply-oversized-provider-reply";
        store
            .create_session_for_actor(
                &identity.authz,
                CreateSessionRequest {
                    id: session_id.into(),
                    title: "Oversized provider reply".into(),
                },
                "create-oversized-provider-reply",
            )
            .await
            .unwrap();

        let calls = Arc::new(AtomicUsize::new(0));
        let provider: Arc<dyn ReplyProvider> =
            Arc::new(OversizedReplyProvider::new(Arc::clone(&calls)));
        let metadata = provider.metadata().clone();
        store
            .start_turn_and_enqueue_reply_for_actor(
                &identity.authz,
                session_id,
                StartTurnRequest {
                    turn_id: turn_id.into(),
                    user_message: "Return a bounded reply".into(),
                    expected_sequence: 1,
                },
                "start-oversized-provider-reply",
                ReplyJobSpec {
                    id: job_id.into(),
                    authz: identity.authz.clone(),
                    provider_name: metadata.provider_id,
                    model_name: metadata.model,
                    request_json: serde_json::to_value(ReplyRequest::new([ReplyMessage::new(
                        ReplyRole::User,
                        "Return a bounded reply",
                    )]))
                    .unwrap(),
                },
            )
            .await
            .unwrap();
        let ReplyClaimOutcome::Claimed(job) = store.claim_next_reply().await.unwrap() else {
            panic!("the reply must be claimable");
        };
        let state = ApiState {
            store: store.clone(),
            durable_ledger_poll_interval: DURABLE_LEDGER_POLL_INTERVAL,
            broadcast_hints_enabled: false,
            auth: None,
            reply: Some(Arc::new(ReplyExecutor::new(provider))),
            sse_capacity: SseCapacity::production(),
        };

        process_reply_job(&state, *job).await.unwrap();

        assert_eq!(calls.load(Ordering::Relaxed), 1);
        let stored = store
            .reply_job_for_actor(&identity.authz, job_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stored.status, runtime::ReplyJobStatus::Failed);
        let error = stored.error_json.unwrap();
        assert_eq!(error["code"], "provider_reply_too_large");
        assert!(
            error["message"].as_str().unwrap().len() <= protocol::REPLY_ERROR_MESSAGE_MAX_BYTES
        );
        let detail = store
            .get_session_for_actor(
                &identity.authz,
                session_id,
                None,
                protocol::COLLECTION_PAGE_DEFAULT_LIMIT,
                None,
                protocol::COLLECTION_PAGE_DEFAULT_LIMIT,
                None,
                protocol::EVENT_PAGE_DEFAULT_LIMIT,
            )
            .await
            .unwrap();
        assert_eq!(detail.session.status, SessionStatus::NeedsAttention);
        assert!(detail.turns[0].assistant_message.is_none());
        assert!(detail.events.iter().all(|event| !matches!(
            &event.data,
            protocol::SessionEventData::AssistantMessage { .. }
        )));
        assert!(matches!(
            store.claim_next_reply().await.unwrap(),
            ReplyClaimOutcome::NotAvailable
        ));
        assert_eq!(calls.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn indeterminate_provider_failures_settle_durably_as_outcome_unknown() {
        for (suffix, failure, expected_code) in [
            ("timeout", IndeterminateFailure::Timeout, "provider_timeout"),
            (
                "transport",
                IndeterminateFailure::Transport,
                "provider_transport_failed",
            ),
            ("panic", IndeterminateFailure::Panic, "provider_panicked"),
        ] {
            let store = DemoStore::seeded().await.unwrap();
            let bootstrap_hash = "d".repeat(64);
            let auth_session_id = AuthSessionId::generate().unwrap();
            let expires_at = (chrono::Utc::now() + chrono::Duration::hours(1))
                .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
            store
                .replace_bootstrap_token(&bootstrap_hash, &expires_at)
                .await
                .unwrap();
            store
                .bootstrap_owner(BootstrapOwnerCommit {
                    bootstrap_token_hash: bootstrap_hash,
                    user_id: "user-owner".into(),
                    username: "owner".into(),
                    password_hash: "$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$ZGlnaWVzdA".into(),
                    auth_session_id: auth_session_id.clone(),
                    session_token_hash: "e".repeat(64),
                    csrf_hash: "f".repeat(64),
                    session_expires_at: expires_at,
                })
                .await
                .unwrap();
            let authz = AuthzContext {
                account_id: AccountId::local(),
                user_id: "user-owner".into(),
                membership_role: MembershipRole::Owner,
                membership_revision: tenancy::MembershipRevision::new(1).unwrap(),
                auth_session_id,
            };
            let session_id = format!("session-{suffix}");
            let turn_id = format!("turn-{suffix}");
            let job_id = format!("reply-{suffix}");
            store
                .create_session_for_actor(
                    &authz,
                    CreateSessionRequest {
                        id: session_id.clone(),
                        title: format!("Indeterminate {suffix}"),
                    },
                    &format!("create-{suffix}"),
                )
                .await
                .unwrap();
            let provider: Arc<dyn ReplyProvider> = Arc::new(IndeterminateProvider::new(failure));
            let metadata = provider.metadata();
            store
                .start_turn_and_enqueue_reply_for_actor(
                    &authz,
                    &session_id,
                    StartTurnRequest {
                        turn_id: turn_id.clone(),
                        user_message: "settle this reply safely".into(),
                        expected_sequence: 1,
                    },
                    &format!("start-{suffix}"),
                    ReplyJobSpec {
                        id: job_id.clone(),
                        authz: authz.clone(),
                        provider_name: metadata.provider_id.clone(),
                        model_name: metadata.model.clone(),
                        request_json: serde_json::to_value(ReplyRequest::new([ReplyMessage::new(
                            ReplyRole::User,
                            "settle this reply safely",
                        )]))
                        .unwrap(),
                    },
                )
                .await
                .unwrap();
            let ReplyClaimOutcome::Claimed(job) = store.claim_next_reply().await.unwrap() else {
                panic!("the reply must be claimable");
            };
            let state = ApiState {
                store: store.clone(),
                durable_ledger_poll_interval: DURABLE_LEDGER_POLL_INTERVAL,
                broadcast_hints_enabled: false,
                auth: None,
                reply: Some(Arc::new(ReplyExecutor::new(provider))),
                sse_capacity: SseCapacity::production(),
            };

            process_reply_job(&state, *job).await.unwrap();

            let stored = store
                .reply_job_for_actor(&authz, &job_id)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(stored.status, runtime::ReplyJobStatus::OutcomeUnknown);
            assert_eq!(stored.error_json.unwrap()["code"], expected_code);
            let detail = store
                .get_session_for_actor(
                    &authz,
                    &session_id,
                    None,
                    protocol::COLLECTION_PAGE_DEFAULT_LIMIT,
                    None,
                    protocol::COLLECTION_PAGE_DEFAULT_LIMIT,
                    None,
                    protocol::EVENT_PAGE_DEFAULT_LIMIT,
                )
                .await
                .unwrap();
            assert_eq!(detail.session.status, SessionStatus::NeedsAttention);
            assert!(matches!(
                &detail.events.last().unwrap().data,
                protocol::SessionEventData::TurnInterrupted { reason, .. }
                    if reason == "assistant reply provider outcome is unknown"
            ));
        }
    }

    #[tokio::test]
    async fn agent_provider_failures_distinguish_known_from_unknown_outcomes() {
        for (suffix, failure, expected_status, expected_code) in [
            (
                "known",
                IndeterminateFailure::Known,
                protocol::AgentTurnStatus::Failed,
                "provider_request_invalid",
            ),
            (
                "secret-unavailable",
                IndeterminateFailure::SecretUnavailable,
                protocol::AgentTurnStatus::Failed,
                "provider_secret_unavailable",
            ),
            (
                "timeout",
                IndeterminateFailure::Timeout,
                protocol::AgentTurnStatus::NeedsAttention,
                "provider_timeout",
            ),
            (
                "transport",
                IndeterminateFailure::Transport,
                protocol::AgentTurnStatus::NeedsAttention,
                "provider_transport_failed",
            ),
            (
                "panic",
                IndeterminateFailure::Panic,
                protocol::AgentTurnStatus::NeedsAttention,
                "provider_panicked",
            ),
        ] {
            let store = DemoStore::seeded().await.unwrap();
            let owner =
                provision_test_owner(&store, "user-agent-failure", "agent-failure-owner").await;
            let session_id = format!("session-agent-{suffix}");
            let turn_id = format!("turn-agent-{suffix}");
            store
                .create_session_for_actor(
                    &owner.authz,
                    CreateSessionRequest {
                        id: session_id.clone(),
                        title: format!("Agent provider {suffix}"),
                    },
                    &format!("create-agent-{suffix}"),
                )
                .await
                .unwrap();
            let app = authenticated_app_with_provider(
                store.clone(),
                false,
                Arc::new(IndeterminateProvider::new(failure)),
            )
            .unwrap();

            let started = app
                .clone()
                .oneshot(
                    Request::post(format!("/api/v1/sessions/{session_id}/turns"))
                        .header(header::HOST, "zeus.test")
                        .header(header::ORIGIN, "http://zeus.test")
                        .header(header::COOKIE, &owner.cookie_header)
                        .header(CSRF_HEADER, &owner.csrf_token)
                        .header(header::CONTENT_TYPE, "application/json")
                        .header("idempotency-key", format!("start-agent-{suffix}"))
                        .body(Body::from(
                            serde_json::json!({
                                "turn_id": turn_id.clone(),
                                "user_message": "classify this provider outcome",
                                "expected_sequence": 1,
                            })
                            .to_string(),
                        ))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(started.status(), StatusCode::ACCEPTED);
            let agent =
                wait_for_agent_status(&store, &owner.authz, &session_id, &turn_id, expected_status)
                    .await;
            assert_eq!(agent.last_error.as_ref().unwrap()["code"], expected_code);
            let session = store
                .get_session_for_actor(
                    &owner.authz,
                    &session_id,
                    None,
                    protocol::COLLECTION_PAGE_DEFAULT_LIMIT,
                    None,
                    protocol::COLLECTION_PAGE_DEFAULT_LIMIT,
                    None,
                    protocol::EVENT_PAGE_DEFAULT_LIMIT,
                )
                .await
                .unwrap();
            assert_eq!(session.session.status, SessionStatus::NeedsAttention);
        }
    }

    #[tokio::test]
    async fn health_and_overview_are_available() {
        let app = test_app().await;

        let health = app
            .clone()
            .oneshot(Request::get("/health/ready").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(health.status(), StatusCode::OK);

        let response = app
            .oneshot(
                Request::get("/api/v1/overview")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let overview: OverviewResponse = response_json(response).await;
        assert_eq!(overview.run.id, DEMO_RUN_ID);
        assert_eq!(overview.run.sequence, 8);
        assert_eq!(overview.recent_events.len(), 8);
    }

    #[tokio::test]
    async fn account_provider_selection_is_secret_free_idempotent_and_binds_new_turns() {
        let store = DemoStore::seeded().await.unwrap();
        let owner = provision_test_owner(&store, "user-provider-owner", "provider-owner").await;
        store
            .create_session_for_actor(
                &owner.authz,
                CreateSessionRequest {
                    id: "session-provider-selection".into(),
                    title: "Provider selection".into(),
                },
                "create-provider-selection-session",
            )
            .await
            .unwrap();
        let model_requests = Arc::new(StdMutex::new(Vec::new()));
        let model_provider: Arc<dyn ReplyProvider> =
            Arc::new(RecordingProvider::new(Arc::clone(&model_requests)));
        let app = authenticated_app_with_provider_registry_and_ingress(
            store.clone(),
            IngressPolicy::direct(false),
            model_provider,
            vec![Arc::new(LocalFallbackProvider::new())],
        )
        .unwrap()
        .layer(MockConnectInfo(test_peer()));

        let catalog = app
            .clone()
            .oneshot(
                Request::get("/api/v1/providers")
                    .header(header::HOST, "zeus.test")
                    .header(header::COOKIE, &owner.cookie_header)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(catalog.status(), StatusCode::OK);
        let catalog: ReplyProviderCatalogResponse = response_json(catalog).await;
        assert_eq!(catalog.default_provider_id, "test-recording-provider");
        assert_eq!(catalog.selected_provider_id, "test-recording-provider");
        assert_eq!(catalog.selected_revision, 0);
        assert_eq!(catalog.providers.len(), 2);
        let catalog_json = serde_json::to_string(&catalog).unwrap();
        for forbidden in ["endpoint", "api_key", "secret_ref", "credential"] {
            assert!(!catalog_json.contains(forbidden));
        }

        let update_body = serde_json::json!({
            "provider_id": "local-fallback",
            "expected_revision": 0,
        })
        .to_string();
        let update = app
            .clone()
            .oneshot(
                Request::put("/api/v1/account/reply-provider")
                    .header(header::HOST, "zeus.test")
                    .header(header::ORIGIN, "http://zeus.test")
                    .header(header::COOKIE, &owner.cookie_header)
                    .header(CSRF_HEADER, &owner.csrf_token)
                    .header(header::CONTENT_TYPE, "application/json")
                    .header("idempotency-key", "select-local-fallback")
                    .body(Body::from(update_body.clone()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(update.status(), StatusCode::OK);
        let update: serde_json::Value = response_json(update).await;
        assert_eq!(update["provider"]["revision"], 1);
        assert_eq!(update["provider"]["provider_id"], "local-fallback");
        assert_eq!(update["provider"]["reply_kind"], "non_model_fallback");
        assert_eq!(update["replayed"], false);

        let replay = app
            .clone()
            .oneshot(
                Request::put("/api/v1/account/reply-provider")
                    .header(header::HOST, "zeus.test")
                    .header(header::ORIGIN, "http://zeus.test")
                    .header(header::COOKIE, &owner.cookie_header)
                    .header(CSRF_HEADER, &owner.csrf_token)
                    .header(header::CONTENT_TYPE, "application/json")
                    .header("idempotency-key", "select-local-fallback")
                    .body(Body::from(update_body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(replay.status(), StatusCode::OK);
        let replay: serde_json::Value = response_json(replay).await;
        assert_eq!(replay["provider"], update["provider"]);
        assert_eq!(replay["replayed"], true);

        let turn = app
            .clone()
            .oneshot(
                Request::post("/api/v1/sessions/session-provider-selection/turns")
                    .header(header::HOST, "zeus.test")
                    .header(header::ORIGIN, "http://zeus.test")
                    .header(header::COOKIE, &owner.cookie_header)
                    .header(CSRF_HEADER, &owner.csrf_token)
                    .header(header::CONTENT_TYPE, "application/json")
                    .header("idempotency-key", "provider-selection-turn")
                    .body(Body::from(
                        serde_json::json!({
                            "turn_id": "turn-provider-selection",
                            "user_message": "Use the selected provider",
                            "expected_sequence": 1,
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(turn.status(), StatusCode::ACCEPTED);
        let settled =
            wait_for_ready_session(&store, &owner.authz, "session-provider-selection").await;
        let provenance = settled.events.iter().find_map(|event| match &event.data {
            protocol::SessionEventData::AssistantMessage { provenance, .. } => provenance.as_ref(),
            _ => None,
        });
        assert_eq!(
            provenance.map(|value| value.provider_id.as_str()),
            Some("local-fallback")
        );
        assert_eq!(
            provenance.map(|value| &value.reply_kind),
            Some(&AssistantReplyKind::NonModelFallback)
        );
        assert!(model_requests.lock().unwrap().is_empty());

        drop(app);
        let restarted = authenticated_app_with_provider(
            store,
            false,
            Arc::new(RecordingProvider::new(model_requests)),
        )
        .unwrap()
        .layer(MockConnectInfo(test_peer()));
        let unavailable = restarted
            .oneshot(
                Request::get("/api/v1/account/reply-provider")
                    .header(header::HOST, "zeus.test")
                    .header(header::COOKIE, &owner.cookie_header)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_problem(
            unavailable,
            StatusCode::SERVICE_UNAVAILABLE,
            "selected_provider_unavailable",
        )
        .await;
    }

    #[tokio::test]
    async fn agent_prompt_api_binds_the_exact_prompt_to_new_agent_execution() {
        let store = DemoStore::seeded().await.unwrap();
        let owner = provision_test_owner(&store, "user-prompt-owner", "prompt-owner").await;
        store
            .create_session_for_actor(
                &owner.authz,
                CreateSessionRequest {
                    id: "session-prompt-binding".into(),
                    title: "Prompt binding".into(),
                },
                "create-session-prompt-binding",
            )
            .await
            .unwrap();
        let requests = Arc::new(StdMutex::new(Vec::new()));
        let app = authenticated_app_with_provider(
            store.clone(),
            false,
            Arc::new(RecordingProvider::new(Arc::clone(&requests))),
        )
        .unwrap()
        .layer(MockConnectInfo(test_peer()));

        let initial = app
            .clone()
            .oneshot(
                Request::get("/api/v1/agent/prompt")
                    .header(header::HOST, "zeus.test")
                    .header(header::COOKIE, &owner.cookie_header)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(initial.status(), StatusCode::OK);
        assert_eq!(initial.headers()[header::CACHE_CONTROL], "no-store");
        let initial: serde_json::Value = response_json(initial).await;
        assert_eq!(initial["revision"], 0);
        assert_eq!(initial["binding_revision"], "1");
        assert_eq!(
            initial["content"],
            runtime::DEFAULT_SESSION_AGENT_SYSTEM_PROMPT
        );

        let content = "You are Zeus under an owner-governed test prompt.";
        let body = serde_json::json!({
            "expected_revision": 0,
            "content": content,
        })
        .to_string();
        let update = app
            .clone()
            .oneshot(
                Request::put("/api/v1/agent/prompt")
                    .header(header::HOST, "zeus.test")
                    .header(header::ORIGIN, "http://zeus.test")
                    .header(header::COOKIE, &owner.cookie_header)
                    .header(CSRF_HEADER, &owner.csrf_token)
                    .header(header::CONTENT_TYPE, "application/json")
                    .header("idempotency-key", "agent-prompt-api-first")
                    .body(Body::from(body.clone()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(update.status(), StatusCode::OK);
        assert_eq!(update.headers()[header::CACHE_CONTROL], "no-store");
        let update: serde_json::Value = response_json(update).await;
        assert_eq!(update["prompt"]["revision"], 1);
        assert_eq!(update["prompt"]["binding_revision"], "2");
        assert_eq!(update["prompt"]["content"], content);
        assert_eq!(update["replayed"], false);

        let replay = app
            .clone()
            .oneshot(
                Request::put("/api/v1/agent/prompt")
                    .header(header::HOST, "zeus.test")
                    .header(header::ORIGIN, "http://zeus.test")
                    .header(header::COOKIE, &owner.cookie_header)
                    .header(CSRF_HEADER, &owner.csrf_token)
                    .header(header::CONTENT_TYPE, "application/json")
                    .header("idempotency-key", "agent-prompt-api-first")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(replay.status(), StatusCode::OK);
        let replay: serde_json::Value = response_json(replay).await;
        assert_eq!(replay["prompt"], update["prompt"]);
        assert_eq!(replay["replayed"], true);

        let history = app
            .clone()
            .oneshot(
                Request::get("/api/v1/agent/prompt/revisions?limit=1")
                    .header(header::HOST, "zeus.test")
                    .header(header::COOKIE, &owner.cookie_header)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(history.status(), StatusCode::OK);
        assert_eq!(history.headers()[header::CACHE_CONTROL], "no-store");
        let history: serde_json::Value = response_json(history).await;
        assert_eq!(history["current_revision"], 1);
        assert_eq!(history["items"][0]["revision"], 1);
        assert_eq!(history["items"][0]["binding_revision"], "2");
        assert_eq!(history["next_before_revision"], serde_json::Value::Null);

        let exact = app
            .clone()
            .oneshot(
                Request::get("/api/v1/agent/prompt/revisions/1")
                    .header(header::HOST, "zeus.test")
                    .header(header::COOKIE, &owner.cookie_header)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(exact.status(), StatusCode::OK);
        let exact: serde_json::Value = response_json(exact).await;
        assert_eq!(exact, update["prompt"]);

        let baseline = app
            .clone()
            .oneshot(
                Request::get("/api/v1/agent/prompt/revisions/0")
                    .header(header::HOST, "zeus.test")
                    .header(header::COOKIE, &owner.cookie_header)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(baseline.status(), StatusCode::OK);
        let baseline: serde_json::Value = response_json(baseline).await;
        assert_eq!(baseline["revision"], 0);
        assert_eq!(baseline["content"], initial["content"]);

        let missing = app
            .clone()
            .oneshot(
                Request::get("/api/v1/agent/prompt/revisions/2")
                    .header(header::HOST, "zeus.test")
                    .header(header::COOKIE, &owner.cookie_header)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_problem(
            missing,
            StatusCode::NOT_FOUND,
            "agent_prompt_revision_not_found",
        )
        .await;

        let noncanonical = app
            .clone()
            .oneshot(
                Request::get("/api/v1/agent/prompt/revisions/01")
                    .header(header::HOST, "zeus.test")
                    .header(header::COOKIE, &owner.cookie_header)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_problem(
            noncanonical,
            StatusCode::BAD_REQUEST,
            "invalid_agent_prompt_revision",
        )
        .await;

        let conflict = app
            .clone()
            .oneshot(
                Request::put("/api/v1/agent/prompt")
                    .header(header::HOST, "zeus.test")
                    .header(header::ORIGIN, "http://zeus.test")
                    .header(header::COOKIE, &owner.cookie_header)
                    .header(CSRF_HEADER, &owner.csrf_token)
                    .header(header::CONTENT_TYPE, "application/json")
                    .header("idempotency-key", "agent-prompt-api-stale")
                    .body(Body::from(
                        serde_json::json!({
                            "expected_revision": 0,
                            "content": "stale replacement",
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_problem(
            conflict,
            StatusCode::CONFLICT,
            "agent_prompt_revision_conflict",
        )
        .await;

        let started = app
            .clone()
            .oneshot(
                Request::post("/api/v1/sessions/session-prompt-binding/turns")
                    .header(header::HOST, "zeus.test")
                    .header(header::ORIGIN, "http://zeus.test")
                    .header(header::COOKIE, &owner.cookie_header)
                    .header(CSRF_HEADER, &owner.csrf_token)
                    .header(header::CONTENT_TYPE, "application/json")
                    .header("idempotency-key", "agent-prompt-bound-turn")
                    .body(Body::from(
                        serde_json::json!({
                            "turn_id": "turn-prompt-binding",
                            "user_message": "Use the governed prompt",
                            "expected_sequence": 1,
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(started.status(), StatusCode::ACCEPTED);
        wait_for_ready_session(&store, &owner.authz, "session-prompt-binding").await;
        {
            let recorded = requests.lock().unwrap();
            assert_eq!(recorded.len(), 1);
            assert_eq!(recorded[0].messages[0].role, ReplyRole::System);
            assert_eq!(recorded[0].messages[0].content, content);
        }

        let explained = app
            .oneshot(
                Request::get(
                    "/api/v1/sessions/session-prompt-binding/turns/turn-prompt-binding/agent/deployment/explain",
                )
                .header(header::HOST, "zeus.test")
                .header(header::COOKIE, &owner.cookie_header)
                .body(Body::empty())
                .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(explained.status(), StatusCode::OK);
        let explained: serde_json::Value = response_json(explained).await;
        assert_eq!(
            explained["persisted_manifest"]["manifest"]["deployment"]["spec"]["prompt"]["revision"],
            "2"
        );
        assert_eq!(explained["matches_current"], true);
    }

    #[tokio::test]
    async fn knowledge_catalog_api_drives_the_active_agent_context() {
        let store = DemoStore::seeded().await.unwrap();
        let owner = provision_test_owner(&store, "user-knowledge-owner", "knowledge-owner").await;
        let app = authenticated_app(store.clone(), false)
            .unwrap()
            .layer(MockConnectInfo(test_peer()));
        store
            .create_session_for_actor(
                &owner.authz,
                CreateSessionRequest {
                    id: "session-knowledge-explain".into(),
                    title: "Knowledge explainability".into(),
                },
                "create-session-knowledge-explain",
            )
            .await
            .unwrap();

        let initial = app
            .clone()
            .oneshot(
                Request::get("/api/v1/knowledge/catalog")
                    .header(header::HOST, "zeus.test")
                    .header(header::COOKIE, &owner.cookie_header)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(initial.status(), StatusCode::OK);
        assert_eq!(initial.headers()[header::CACHE_CONTROL], "no-store");
        let initial: serde_json::Value = response_json(initial).await;
        assert_eq!(initial["revision"], 0);
        assert_eq!(initial["corpus"]["entries"], serde_json::json!([]));

        let body = serde_json::json!({
            "expected_revision": 0,
            "entries": [{
                "entry_id": "execution-epochs",
                "revision": "1",
                "title": "Immutable execution epochs",
                "content": "Zeus binds every approved incident action to an immutable execution epoch."
            }]
        })
        .to_string();
        let update = app
            .clone()
            .oneshot(
                Request::put("/api/v1/knowledge/catalog")
                    .header(header::HOST, "zeus.test")
                    .header(header::ORIGIN, "http://zeus.test")
                    .header(header::COOKIE, &owner.cookie_header)
                    .header(CSRF_HEADER, &owner.csrf_token)
                    .header(header::CONTENT_TYPE, "application/json")
                    .header("idempotency-key", "knowledge-api-first")
                    .body(Body::from(body.clone()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(update.status(), StatusCode::OK);
        assert_eq!(update.headers()[header::CACHE_CONTROL], "no-store");
        let update: serde_json::Value = response_json(update).await;
        assert_eq!(update["catalog"]["revision"], 1);
        assert_eq!(update["replayed"], false);

        let started = app
            .clone()
            .oneshot(
                Request::post("/api/v1/sessions/session-knowledge-explain/turns")
                    .header(header::HOST, "zeus.test")
                    .header(header::ORIGIN, "http://zeus.test")
                    .header(header::COOKIE, &owner.cookie_header)
                    .header(CSRF_HEADER, &owner.csrf_token)
                    .header(header::CONTENT_TYPE, "application/json")
                    .header("idempotency-key", "knowledge-explain-turn")
                    .body(Body::from(
                        serde_json::json!({
                            "turn_id": "turn-knowledge-explain",
                            "user_message": "explain the immutable execution epoch",
                            "expected_sequence": 1,
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(started.status(), StatusCode::ACCEPTED);

        let explained = app
            .clone()
            .oneshot(
                Request::get(
                    "/api/v1/sessions/session-knowledge-explain/turns/turn-knowledge-explain/agent/knowledge/explain",
                )
                .header(header::HOST, "zeus.test")
                .header(header::COOKIE, &owner.cookie_header)
                .body(Body::empty())
                .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(explained.status(), StatusCode::OK);
        assert_eq!(explained.headers()[header::CACHE_CONTROL], "no-store");
        let explained: serde_json::Value = response_json(explained).await;
        assert_eq!(explained["legacy_unbound"], false);
        assert_eq!(
            explained["context"]["corpus_digest"],
            update["catalog"]["corpus"]["digest"]
        );
        assert_eq!(
            explained["context"]["snapshot"]["snapshot"]["hits"][0]["entry"]["entry_id"],
            "execution-epochs"
        );
        assert!(explained["context"].get("corpus").is_none());

        let replay = app
            .clone()
            .oneshot(
                Request::put("/api/v1/knowledge/catalog")
                    .header(header::HOST, "zeus.test")
                    .header(header::ORIGIN, "http://zeus.test")
                    .header(header::COOKIE, &owner.cookie_header)
                    .header(CSRF_HEADER, &owner.csrf_token)
                    .header(header::CONTENT_TYPE, "application/json")
                    .header("idempotency-key", "knowledge-api-first")
                    .body(Body::from(body.clone()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(replay.status(), StatusCode::OK);
        let replay: serde_json::Value = response_json(replay).await;
        assert_eq!(replay["catalog"], update["catalog"]);
        assert_eq!(replay["replayed"], true);

        let second_body = serde_json::json!({
            "expected_revision": 1,
            "entries": [{
                "entry_id": "knowledge-governance",
                "revision": "1",
                "title": "Knowledge governance",
                "content": "Catalog recovery creates a new revision from exact historical corpus material."
            }]
        })
        .to_string();
        let second = app
            .clone()
            .oneshot(
                Request::put("/api/v1/knowledge/catalog")
                    .header(header::HOST, "zeus.test")
                    .header(header::ORIGIN, "http://zeus.test")
                    .header(header::COOKIE, &owner.cookie_header)
                    .header(CSRF_HEADER, &owner.csrf_token)
                    .header(header::CONTENT_TYPE, "application/json")
                    .header("idempotency-key", "knowledge-api-second")
                    .body(Body::from(second_body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(second.status(), StatusCode::OK);
        let second: serde_json::Value = response_json(second).await;
        assert_eq!(second["catalog"]["revision"], 2);

        let history = app
            .clone()
            .oneshot(
                Request::get("/api/v1/knowledge/catalog/revisions?limit=1")
                    .header(header::HOST, "zeus.test")
                    .header(header::COOKIE, &owner.cookie_header)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(history.status(), StatusCode::OK);
        assert_eq!(history.headers()[header::CACHE_CONTROL], "no-store");
        let history: serde_json::Value = response_json(history).await;
        assert_eq!(history["current_revision"], 2);
        assert_eq!(history["items"].as_array().unwrap().len(), 1);
        assert_eq!(history["items"][0]["revision"], 2);
        assert_eq!(history["items"][0]["entry_count"], 1);
        assert_eq!(history["next_before_revision"], 2);

        let older = app
            .clone()
            .oneshot(
                Request::get("/api/v1/knowledge/catalog/revisions?before_revision=2&limit=1")
                    .header(header::HOST, "zeus.test")
                    .header(header::COOKIE, &owner.cookie_header)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(older.status(), StatusCode::OK);
        let older: serde_json::Value = response_json(older).await;
        assert_eq!(older["items"][0]["revision"], 1);
        assert!(older["next_before_revision"].is_null());

        let historical = app
            .clone()
            .oneshot(
                Request::get("/api/v1/knowledge/catalog/revisions/1")
                    .header(header::HOST, "zeus.test")
                    .header(header::COOKIE, &owner.cookie_header)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(historical.status(), StatusCode::OK);
        assert_eq!(historical.headers()[header::CACHE_CONTROL], "no-store");
        let historical: serde_json::Value = response_json(historical).await;
        assert_eq!(historical["revision"], 1);
        assert_eq!(
            historical["corpus"]["entries"][0]["entry_id"],
            "execution-epochs"
        );

        let baseline = app
            .clone()
            .oneshot(
                Request::get("/api/v1/knowledge/catalog/revisions/0")
                    .header(header::HOST, "zeus.test")
                    .header(header::COOKIE, &owner.cookie_header)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(baseline.status(), StatusCode::OK);
        let baseline: serde_json::Value = response_json(baseline).await;
        assert_eq!(baseline["revision"], 0);
        assert_eq!(baseline["corpus"]["entries"], serde_json::json!([]));

        let restored = app
            .clone()
            .oneshot(
                Request::put("/api/v1/knowledge/catalog")
                    .header(header::HOST, "zeus.test")
                    .header(header::ORIGIN, "http://zeus.test")
                    .header(header::COOKIE, &owner.cookie_header)
                    .header(CSRF_HEADER, &owner.csrf_token)
                    .header(header::CONTENT_TYPE, "application/json")
                    .header("idempotency-key", "knowledge-api-restore-first")
                    .body(Body::from(
                        serde_json::json!({
                            "expected_revision": 2,
                            "entries": historical["corpus"]["entries"].clone(),
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(restored.status(), StatusCode::OK);
        let restored: serde_json::Value = response_json(restored).await;
        assert_eq!(restored["catalog"]["revision"], 3);
        assert_eq!(
            restored["catalog"]["corpus"]["digest"],
            historical["corpus"]["digest"]
        );

        let missing = app
            .clone()
            .oneshot(
                Request::get("/api/v1/knowledge/catalog/revisions/4")
                    .header(header::HOST, "zeus.test")
                    .header(header::COOKIE, &owner.cookie_header)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_problem(
            missing,
            StatusCode::NOT_FOUND,
            "knowledge_catalog_revision_not_found",
        )
        .await;

        let noncanonical = app
            .clone()
            .oneshot(
                Request::get("/api/v1/knowledge/catalog/revisions/01")
                    .header(header::HOST, "zeus.test")
                    .header(header::COOKIE, &owner.cookie_header)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_problem(
            noncanonical,
            StatusCode::BAD_REQUEST,
            "invalid_knowledge_catalog_revision",
        )
        .await;

        let invalid_page = app
            .clone()
            .oneshot(
                Request::get("/api/v1/knowledge/catalog/revisions?before_revision=0")
                    .header(header::HOST, "zeus.test")
                    .header(header::COOKIE, &owner.cookie_header)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_problem(invalid_page, StatusCode::BAD_REQUEST, "invalid_page_cursor").await;

        let stale = app
            .clone()
            .oneshot(
                Request::put("/api/v1/knowledge/catalog")
                    .header(header::HOST, "zeus.test")
                    .header(header::ORIGIN, "http://zeus.test")
                    .header(header::COOKIE, &owner.cookie_header)
                    .header(CSRF_HEADER, &owner.csrf_token)
                    .header(header::CONTENT_TYPE, "application/json")
                    .header("idempotency-key", "knowledge-api-stale")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_problem(
            stale,
            StatusCode::CONFLICT,
            "knowledge_catalog_revision_conflict",
        )
        .await;

        let context = store
            .session_agent_knowledge_context(&owner.authz, "explain the immutable execution epoch")
            .await
            .unwrap();
        assert_eq!(context.corpus.entries().len(), 1);
        assert_eq!(
            context.snapshot.snapshot().hits()[0].entry().entry_id(),
            "execution-epochs"
        );
        assert!(
            context
                .snapshot
                .snapshot()
                .canonical_context()
                .contains("Zeus binds every approved incident action")
        );
    }

    #[tokio::test]
    async fn authenticated_app_bootstraps_once_and_enforces_session_csrf_and_logout() {
        let store = DemoStore::seeded().await.unwrap();
        let bootstrap_token = BootstrapToken::generate().unwrap();
        let expires_at = (chrono::Utc::now() + chrono::Duration::minutes(15))
            .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        store
            .replace_bootstrap_token(&bootstrap_token.digest().to_persistence(), &expires_at)
            .await
            .unwrap();
        let app = authenticated_app(store, false)
            .unwrap()
            .layer(MockConnectInfo(test_peer()));

        let health = app
            .clone()
            .oneshot(Request::get("/health/ready").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(health.status(), StatusCode::OK);

        let protected = app
            .clone()
            .oneshot(
                Request::get("/api/v1/overview")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(protected.status(), StatusCode::UNAUTHORIZED);

        let bootstrap = app
            .clone()
            .oneshot(
                Request::post("/api/v1/auth/bootstrap")
                    .header(header::HOST, "zeus.test")
                    .header(header::ORIGIN, "http://zeus.test")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "bootstrap_token": bootstrap_token.expose_secret(),
                            "username": "owner",
                            "password": "Owner-password-2026",
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(bootstrap.status(), StatusCode::OK);
        assert_eq!(bootstrap.headers()[header::CACHE_CONTROL], "no-store");
        let cookie_header = authentication_cookie_header(bootstrap.headers());
        let set_cookies = bootstrap
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .map(|value| value.to_str().unwrap().to_owned())
            .collect::<Vec<_>>();
        assert_eq!(set_cookies.len(), 2);
        assert!(
            set_cookies
                .iter()
                .all(|value| value.contains("SameSite=Strict"))
        );
        assert!(set_cookies.iter().all(|value| !value.contains("; Secure")));
        assert!(
            set_cookies
                .iter()
                .find(|value| value.starts_with("zeus_session="))
                .unwrap()
                .contains("HttpOnly")
        );
        assert!(
            !set_cookies
                .iter()
                .find(|value| value.starts_with("zeus_csrf="))
                .unwrap()
                .contains("HttpOnly")
        );
        let authentication: AuthenticationResponse = response_json(bootstrap).await;
        assert_eq!(authentication.user.username, "owner");

        let second_bootstrap = app
            .clone()
            .oneshot(
                Request::post("/api/v1/auth/bootstrap")
                    .header(header::HOST, "zeus.test")
                    .header(header::ORIGIN, "http://zeus.test")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "bootstrap_token": bootstrap_token.expose_secret(),
                            "username": "other-owner",
                            "password": "Other-password-2026",
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(second_bootstrap.status(), StatusCode::CONFLICT);

        let authenticated = app
            .clone()
            .oneshot(
                Request::get("/api/v1/overview")
                    .header(header::COOKIE, &cookie_header)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(authenticated.status(), StatusCode::OK);

        let missing_csrf = app
            .clone()
            .oneshot(
                Request::patch("/api/v1/me/settings")
                    .header(header::HOST, "zeus.test")
                    .header(header::ORIGIN, "http://zeus.test")
                    .header(header::COOKIE, &cookie_header)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "theme": "dark",
                            "preferred_model": null,
                            "expected_revision": authentication.preferences.revision,
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(missing_csrf.status(), StatusCode::FORBIDDEN);

        let settings = app
            .clone()
            .oneshot(
                Request::patch("/api/v1/me/settings")
                    .header(header::HOST, "zeus.test")
                    .header(header::ORIGIN, "http://zeus.test")
                    .header(header::COOKIE, &cookie_header)
                    .header(CSRF_HEADER, &authentication.csrf_token)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "theme": "dark",
                            "preferred_model": null,
                            "expected_revision": authentication.preferences.revision,
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(settings.status(), StatusCode::OK);
        let settings: UserPreferences = response_json(settings).await;
        assert_eq!(settings.theme, ThemePreference::Dark);
        assert_eq!(settings.revision, authentication.preferences.revision + 1);

        let created = app
            .clone()
            .oneshot(
                Request::post("/api/v1/sessions")
                    .header(header::HOST, "zeus.test")
                    .header(header::ORIGIN, "http://zeus.test")
                    .header(header::COOKIE, &cookie_header)
                    .header(CSRF_HEADER, &authentication.csrf_token)
                    .header(header::CONTENT_TYPE, "application/json")
                    .header("idempotency-key", "authenticated-create-session")
                    .body(Body::from(
                        r#"{"id":"session-auth-reply","title":"Authenticated reply"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(created.status(), StatusCode::CREATED);
        let created: CreateSessionResponse = response_json(created).await;
        assert_eq!(created.session.sequence, 1);

        let started = app
            .clone()
            .oneshot(
                Request::post("/api/v1/sessions/session-auth-reply/turns")
                    .header(header::HOST, "zeus.test")
                    .header(header::ORIGIN, "http://zeus.test")
                    .header(header::COOKIE, &cookie_header)
                    .header(CSRF_HEADER, &authentication.csrf_token)
                    .header(header::CONTENT_TYPE, "application/json")
                    .header("idempotency-key", "authenticated-start-turn")
                    .body(Body::from(
                        r#"{"turn_id":"turn-auth-reply","user_message":"Reply to me","expected_sequence":1}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(started.status(), StatusCode::ACCEPTED);

        let replied = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let response = app
                    .clone()
                    .oneshot(
                        Request::get("/api/v1/sessions/session-auth-reply")
                            .header(header::COOKIE, &cookie_header)
                            .body(Body::empty())
                            .unwrap(),
                    )
                    .await
                    .unwrap();
                assert_eq!(response.status(), StatusCode::OK);
                let detail: SessionDetail = response_json(response).await;
                if detail.session.status == SessionStatus::Ready {
                    break detail;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("the local fallback reply should settle durably");
        assert_eq!(replied.turns.len(), 1);
        assert_eq!(
            replied.turns[0].assistant_message.as_deref(),
            Some("Your message was saved, but no model provider is configured.")
        );
        assert_eq!(replied.events.len(), 4);
        assert!(matches!(
            &replied.events[2].data,
            protocol::SessionEventData::AssistantMessage {
                provenance: Some(AssistantReplyProvenance {
                    provider_id,
                    model: None,
                    reply_kind: AssistantReplyKind::NonModelFallback,
                }),
                ..
            } if provider_id == "local-fallback"
        ));
        assert!(matches!(
            replied.events[3].data,
            protocol::SessionEventData::TurnFlushed { .. }
        ));

        let browser_flush = app
            .clone()
            .oneshot(
                Request::post("/api/v1/sessions/session-ZR-1842/turns/turn-1/flush")
                    .header(header::HOST, "zeus.test")
                    .header(header::ORIGIN, "http://zeus.test")
                    .header(header::COOKIE, &cookie_header)
                    .header(CSRF_HEADER, &authentication.csrf_token)
                    .header(header::CONTENT_TYPE, "application/json")
                    .header("idempotency-key", "forged-browser-flush")
                    .body(Body::from(
                        r#"{"turn_id":"turn-1","assistant_message":"forged","expected_sequence":2}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(browser_flush.status(), StatusCode::NOT_FOUND);

        let sse = app
            .clone()
            .oneshot(
                Request::get("/api/v1/sessions/session-ZR-1842/events?after=2")
                    .header(header::COOKIE, &cookie_header)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(sse.status(), StatusCode::OK);
        let mut sse_body = sse.into_body();
        let opened = tokio::time::timeout(Duration::from_secs(1), sse_body.frame())
            .await
            .expect("authenticated SSE should open immediately")
            .expect("authenticated SSE should produce an opening frame")
            .expect("authenticated SSE opening frame should be valid");
        assert!(
            String::from_utf8(opened.into_data().unwrap().to_vec())
                .unwrap()
                .contains("stream-open")
        );

        let logout = app
            .clone()
            .oneshot(
                Request::post("/api/v1/auth/logout")
                    .header(header::HOST, "zeus.test")
                    .header(header::ORIGIN, "http://zeus.test")
                    .header(header::COOKIE, &cookie_header)
                    .header(CSRF_HEADER, &authentication.csrf_token)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(logout.status(), StatusCode::OK);
        assert_eq!(
            logout.headers().get_all(header::SET_COOKIE).iter().count(),
            2
        );

        let ended = tokio::time::timeout(Duration::from_secs(3), sse_body.frame())
            .await
            .expect("revoked SSE should close by the next durable auth poll");
        assert!(ended.is_none(), "revoked SSE emitted another frame");

        let revoked = app
            .oneshot(
                Request::get("/api/v1/overview")
                    .header(header::COOKIE, cookie_header)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(revoked.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            revoked.headers()[header::CACHE_CONTROL],
            HeaderValue::from_static("no-store")
        );
    }

    #[tokio::test]
    async fn cross_account_rest_and_sse_are_not_found_and_live_sse_closes_on_account_change() {
        let (app, store, alice, path) = authenticated_file_app("cross-actor").await;
        let bob = insert_test_member(&path, "user-bob", "bob");
        let session_id = "session-cross-actor";

        let created = app
            .clone()
            .oneshot(
                Request::post("/api/v1/sessions")
                    .header(header::HOST, "zeus.test")
                    .header(header::ORIGIN, "http://zeus.test")
                    .header(header::COOKIE, &alice.cookie_header)
                    .header(CSRF_HEADER, &alice.csrf_token)
                    .header(header::CONTENT_TYPE, "application/json")
                    .header("idempotency-key", "create-cross-actor")
                    .body(Body::from(
                        serde_json::json!({
                            "id": session_id,
                            "title": "Cross actor boundary",
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(created.status(), StatusCode::CREATED);

        let sse = app
            .clone()
            .oneshot(
                Request::get(format!("/api/v1/sessions/{session_id}/events?after=1"))
                    .header(header::COOKIE, &alice.cookie_header)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(sse.status(), StatusCode::OK);
        let mut sse_body = sse.into_body();
        let opened = tokio::time::timeout(Duration::from_secs(1), sse_body.frame())
            .await
            .expect("owned SSE should open immediately")
            .expect("owned SSE should produce an opening frame")
            .expect("owned SSE opening frame should be valid");
        assert!(
            String::from_utf8(opened.into_data().unwrap().to_vec())
                .unwrap()
                .contains("stream-open")
        );

        // Production account ownership is immutable. This test-only database
        // mutation simulates a future administrative transfer and proves the
        // stream does not keep relying on its open-time authorization snapshot.
        transfer_test_session(&path, session_id, &bob.user_id);
        let ended = tokio::time::timeout(Duration::from_secs(3), sse_body.frame())
            .await
            .expect("ownership-changed SSE should close by the next durable poll");
        assert!(
            ended.is_none(),
            "ownership-changed SSE emitted another frame"
        );

        let detail = app
            .clone()
            .oneshot(
                Request::get(format!("/api/v1/sessions/{session_id}"))
                    .header(header::COOKIE, &alice.cookie_header)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(detail.status(), StatusCode::NOT_FOUND);
        let problem: ProblemDetails = response_json(detail).await;
        assert_eq!(problem.code, "session_not_found");

        let foreign_execution_explain = app
            .clone()
            .oneshot(
                Request::get(format!(
                    "/api/v1/sessions/{session_id}/turns/turn-cross-actor/agent/execution/explain"
                ))
                .header(header::HOST, "zeus.test")
                .header(header::COOKIE, &alice.cookie_header)
                .body(Body::empty())
                .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(foreign_execution_explain.status(), StatusCode::NOT_FOUND);
        assert_eq!(
            foreign_execution_explain
                .headers()
                .get(header::CACHE_CONTROL),
            Some(&HeaderValue::from_static("no-store"))
        );
        let problem: ProblemDetails = response_json(foreign_execution_explain).await;
        assert_eq!(problem.code, "session_not_found");

        let malformed_foreign_epoch = app
            .clone()
            .oneshot(
                Request::get(format!(
                    "/api/v1/sessions/{session_id}/turns/turn-cross-actor/agent/execution/epochs/not-a-step"
                ))
                .header(header::HOST, "zeus.test")
                .header(header::COOKIE, &alice.cookie_header)
                .body(Body::empty())
                .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(malformed_foreign_epoch.status(), StatusCode::NOT_FOUND);
        assert_eq!(
            malformed_foreign_epoch.headers().get(header::CACHE_CONTROL),
            Some(&HeaderValue::from_static("no-store"))
        );
        let problem: ProblemDetails = response_json(malformed_foreign_epoch).await;
        assert_eq!(problem.code, "session_not_found");

        let malformed_foreign_cursor = app
            .clone()
            .oneshot(
                Request::get(format!(
                    "/api/v1/sessions/{session_id}?events_before=not-a-canonical-cursor"
                ))
                .header(header::COOKIE, &alice.cookie_header)
                .body(Body::empty())
                .unwrap(),
            )
            .await
            .unwrap();
        assert_problem(
            malformed_foreign_cursor,
            StatusCode::NOT_FOUND,
            "session_not_found",
        )
        .await;

        let malformed_foreign_limit = app
            .clone()
            .oneshot(
                Request::get(format!(
                    "/api/v1/sessions/{session_id}?events_limit=not-a-number"
                ))
                .header(header::COOKIE, &alice.cookie_header)
                .body(Body::empty())
                .unwrap(),
            )
            .await
            .unwrap();
        assert_problem(
            malformed_foreign_limit,
            StatusCode::NOT_FOUND,
            "session_not_found",
        )
        .await;

        let malformed_foreign_turn = app
            .clone()
            .oneshot(
                Request::get(format!(
                    "/api/v1/sessions/{session_id}/turns/%20malformed-turn%20"
                ))
                .header(header::COOKIE, &alice.cookie_header)
                .body(Body::empty())
                .unwrap(),
            )
            .await
            .unwrap();
        assert_problem(
            malformed_foreign_turn,
            StatusCode::NOT_FOUND,
            "session_not_found",
        )
        .await;

        let resume = app
            .clone()
            .oneshot(
                Request::post(format!("/api/v1/sessions/{session_id}/resume"))
                    .header(header::HOST, "zeus.test")
                    .header(header::ORIGIN, "http://zeus.test")
                    .header(header::COOKIE, &alice.cookie_header)
                    .header(CSRF_HEADER, &alice.csrf_token)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from("not-json"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resume.status(), StatusCode::NOT_FOUND);

        let start_turn = app
            .clone()
            .oneshot(
                Request::post(format!("/api/v1/sessions/{session_id}/turns"))
                    .header(header::HOST, "zeus.test")
                    .header(header::ORIGIN, "http://zeus.test")
                    .header(header::COOKIE, &alice.cookie_header)
                    .header(CSRF_HEADER, &alice.csrf_token)
                    .header(header::CONTENT_TYPE, "application/json")
                    .header("idempotency-key", "turn-cross-actor")
                    .body(Body::from(
                        r#"{"turn_id":"turn-cross-actor","user_message":"private","expected_sequence":1}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(start_turn.status(), StatusCode::NOT_FOUND);

        let cross_actor_sse = app
            .clone()
            .oneshot(
                Request::get(format!("/api/v1/sessions/{session_id}/events?after=2"))
                    .header(header::COOKIE, &alice.cookie_header)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(cross_actor_sse.status(), StatusCode::NOT_FOUND);

        let malformed_foreign_sse = app
            .clone()
            .oneshot(
                Request::get(format!(
                    "/api/v1/sessions/{session_id}/events?after=not-a-number"
                ))
                .header(header::COOKIE, &alice.cookie_header)
                .body(Body::empty())
                .unwrap(),
            )
            .await
            .unwrap();
        assert_problem(
            malformed_foreign_sse,
            StatusCode::NOT_FOUND,
            "session_not_found",
        )
        .await;

        let sessions = app
            .clone()
            .oneshot(
                Request::get("/api/v1/sessions")
                    .header(header::COOKIE, &alice.cookie_header)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(sessions.status(), StatusCode::OK);
        let sessions: Vec<SessionSummary> = response_json(sessions).await;
        assert!(!sessions.iter().any(|session| session.id == session_id));

        let member_owned = app
            .clone()
            .oneshot(
                Request::get("/api/v1/sessions/session-ZR-1842")
                    .header(header::COOKIE, &bob.cookie_header)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(member_owned.status(), StatusCode::OK);

        drop(app);
        drop(store);
        cleanup_test_database(&path);
    }

    #[tokio::test]
    async fn cross_account_run_rest_review_and_sse_are_not_found_and_live_sse_closes() {
        let (app, store, alice, path) = authenticated_file_app("cross-run").await;
        let bob = insert_test_member(&path, "user-bob-run", "bob-run");

        let sse = app
            .clone()
            .oneshot(
                Request::get(format!("/api/v1/runs/{DEMO_RUN_ID}/events?after=8"))
                    .header(header::COOKIE, &alice.cookie_header)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(sse.status(), StatusCode::OK);
        let mut body = sse.into_body();
        let opened = tokio::time::timeout(Duration::from_secs(1), body.frame())
            .await
            .expect("owned Run SSE should open immediately")
            .expect("owned Run SSE should produce an opening frame")
            .expect("owned Run SSE opening frame should be valid");
        assert!(
            String::from_utf8(opened.into_data().unwrap().to_vec())
                .unwrap()
                .contains("stream-open")
        );

        transfer_test_run(&path, DEMO_RUN_ID, &bob.user_id);
        let ended = tokio::time::timeout(Duration::from_secs(3), body.frame())
            .await
            .expect("ownership-changed Run SSE should close by the next durable poll");
        assert!(
            ended.is_none(),
            "ownership-changed Run SSE emitted another frame"
        );

        let detail = app
            .clone()
            .oneshot(
                Request::get(format!("/api/v1/runs/{DEMO_RUN_ID}"))
                    .header(header::COOKIE, &alice.cookie_header)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(detail.status(), StatusCode::NOT_FOUND);
        let problem: ProblemDetails = response_json(detail).await;
        assert_eq!(problem.code, "run_not_found");

        let malformed_foreign_cursor = app
            .clone()
            .oneshot(
                Request::get(format!(
                    "/api/v1/runs/{DEMO_RUN_ID}?events_before=not-a-canonical-cursor"
                ))
                .header(header::COOKIE, &alice.cookie_header)
                .body(Body::empty())
                .unwrap(),
            )
            .await
            .unwrap();
        assert_problem(
            malformed_foreign_cursor,
            StatusCode::NOT_FOUND,
            "run_not_found",
        )
        .await;

        let malformed_foreign_limit = app
            .clone()
            .oneshot(
                Request::get(format!(
                    "/api/v1/runs/{DEMO_RUN_ID}?events_limit=not-a-number"
                ))
                .header(header::COOKIE, &alice.cookie_header)
                .body(Body::empty())
                .unwrap(),
            )
            .await
            .unwrap();
        assert_problem(
            malformed_foreign_limit,
            StatusCode::NOT_FOUND,
            "run_not_found",
        )
        .await;

        let review = app
            .clone()
            .oneshot(
                Request::post(format!(
                    "/api/v1/runs/{DEMO_RUN_ID}/approvals/APR-901/decision"
                ))
                .header(header::HOST, "zeus.test")
                .header(header::ORIGIN, "http://zeus.test")
                .header(header::COOKIE, &alice.cookie_header)
                .header(CSRF_HEADER, &alice.csrf_token)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from("not-json"))
                .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(review.status(), StatusCode::NOT_FOUND);

        let cross_actor_sse = app
            .clone()
            .oneshot(
                Request::get(format!("/api/v1/runs/{DEMO_RUN_ID}/events?after=9"))
                    .header(header::COOKIE, &alice.cookie_header)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(cross_actor_sse.status(), StatusCode::NOT_FOUND);

        let malformed_foreign_sse = app
            .clone()
            .oneshot(
                Request::get(format!(
                    "/api/v1/runs/{DEMO_RUN_ID}/events?after=not-a-number"
                ))
                .header(header::COOKIE, &alice.cookie_header)
                .body(Body::empty())
                .unwrap(),
            )
            .await
            .unwrap();
        assert_problem(
            malformed_foreign_sse,
            StatusCode::NOT_FOUND,
            "run_not_found",
        )
        .await;

        let overview = app
            .clone()
            .oneshot(
                Request::get("/api/v1/overview")
                    .header(header::COOKIE, &alice.cookie_header)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(overview.status(), StatusCode::NOT_FOUND);

        drop(app);
        drop(store);
        cleanup_test_database(&path);
    }

    #[tokio::test]
    async fn legacy_user_role_mutation_does_not_change_authority_but_membership_revision_does() {
        let (app, store, alice, path) = authenticated_file_app("role-change").await;
        let sse = app
            .clone()
            .oneshot(
                Request::get("/api/v1/sessions/session-ZR-1842/events?after=2")
                    .header(header::COOKIE, &alice.cookie_header)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(sse.status(), StatusCode::OK);
        let mut body = sse.into_body();
        let opened = tokio::time::timeout(Duration::from_secs(1), body.frame())
            .await
            .expect("owner SSE should open immediately")
            .expect("owner SSE should produce an opening frame")
            .expect("owner SSE opening frame should be valid");
        assert!(
            String::from_utf8(opened.into_data().unwrap().to_vec())
                .unwrap()
                .contains("stream-open")
        );

        change_test_user_role(&path, &alice.user_id, "member");
        let accepted = app
            .clone()
            .oneshot(
                Request::get("/api/v1/overview")
                    .header(header::COOKIE, &alice.cookie_header)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(accepted.status(), StatusCode::OK);
        let status = app
            .clone()
            .oneshot(
                Request::get("/api/v1/auth/status")
                    .header(header::COOKIE, &alice.cookie_header)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(status.status(), StatusCode::OK);
        let status: AuthStatusResponse = response_json(status).await;
        assert_eq!(status.user.unwrap().role, AccountRole::Owner);

        let legacy_role_did_not_close =
            tokio::time::timeout(Duration::from_secs(3), body.frame()).await;
        assert!(
            legacy_role_did_not_close.is_err(),
            "legacy users.role unexpectedly changed the live SSE authority"
        );

        bump_test_membership_revision(&path, &alice.user_id);
        let ended = tokio::time::timeout(Duration::from_secs(3), body.frame())
            .await
            .expect("membership revision change should close SSE by the next durable poll");
        assert!(
            ended.is_none(),
            "membership-revision-changed SSE emitted another frame"
        );

        let rejected = app
            .clone()
            .oneshot(
                Request::get("/api/v1/overview")
                    .header(header::COOKIE, &alice.cookie_header)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(rejected.status(), StatusCode::UNAUTHORIZED);

        drop(body);
        drop(app);
        drop(store);
        cleanup_test_database(&path);
    }

    #[tokio::test]
    async fn membership_account_and_user_status_changes_revoke_cookie_and_live_sse() {
        for authority in ["membership", "account", "user"] {
            let (app, store, owner, path) =
                authenticated_file_app(&format!("{authority}-status-revocation")).await;
            let sse = app
                .clone()
                .oneshot(
                    Request::get("/api/v1/sessions/session-ZR-1842/events?after=2")
                        .header(header::COOKIE, &owner.cookie_header)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(sse.status(), StatusCode::OK);
            let mut body = sse.into_body();
            let opened = tokio::time::timeout(Duration::from_secs(1), body.frame())
                .await
                .expect("owner SSE should open immediately")
                .expect("owner SSE should produce an opening frame")
                .expect("owner SSE opening frame should be valid");
            assert!(
                String::from_utf8(opened.into_data().unwrap().to_vec())
                    .unwrap()
                    .contains("stream-open")
            );

            invalidate_test_authority(&path, &owner.user_id, authority);
            let ended = tokio::time::timeout(Duration::from_secs(3), body.frame())
                .await
                .unwrap_or_else(|_| panic!("{authority} status change did not revalidate SSE"));
            assert!(
                ended.is_none(),
                "{authority} status change emitted another SSE frame"
            );

            let rejected = app
                .clone()
                .oneshot(
                    Request::get("/api/v1/overview")
                        .header(header::COOKIE, &owner.cookie_header)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(rejected.status(), StatusCode::UNAUTHORIZED);

            drop(body);
            drop(app);
            drop(store);
            cleanup_test_database(&path);
        }
    }

    #[tokio::test]
    async fn review_endpoint_is_idempotent() {
        let app = test_app().await;
        let request = || {
            Request::post(format!(
                "/api/v1/runs/{DEMO_RUN_ID}/approvals/APR-901/decision"
            ))
            .header(header::CONTENT_TYPE, "application/json")
            .header("idempotency-key", "api-review-1")
            .body(Body::from(r#"{"decision":"approve","note":"ship it"}"#))
            .unwrap()
        };

        let first = app.clone().oneshot(request()).await.unwrap();
        assert_eq!(first.status(), StatusCode::OK);
        let first: ReviewResponse = response_json(first).await;
        let second = app.clone().oneshot(request()).await.unwrap();
        assert_eq!(second.status(), StatusCode::OK);
        let second: ReviewResponse = response_json(second).await;

        assert!(!first.replayed);
        assert!(second.replayed);
        assert_eq!(first.event.sequence, 9);
        assert_eq!(first.event, second.event);

        let detail = app
            .oneshot(
                Request::get(format!("/api/v1/runs/{DEMO_RUN_ID}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let detail: RunDetail = response_json(detail).await;
        assert!(detail.events.len() >= 9);
        assert_eq!(
            detail
                .events
                .iter()
                .filter(|event| matches!(
                    event.data,
                    Some(protocol::RunEventData::ApprovalDecided { .. })
                ))
                .count(),
            1
        );
    }

    #[tokio::test]
    async fn session_create_list_and_get_are_idempotent() {
        let app = test_app().await;
        let request = || {
            Request::post("/api/v1/sessions")
                .header(header::CONTENT_TYPE, "application/json")
                .header("idempotency-key", "api-create-session-1")
                .body(Body::from(
                    r#"{"id":"session-api","title":"API conversation"}"#,
                ))
                .unwrap()
        };

        let first = app.clone().oneshot(request()).await.unwrap();
        assert_eq!(first.status(), StatusCode::CREATED);
        let first: CreateSessionResponse = response_json(first).await;
        assert!(!first.replayed);
        assert_eq!(first.session.sequence, 1);

        let second = app.clone().oneshot(request()).await.unwrap();
        assert_eq!(second.status(), StatusCode::CREATED);
        let second: CreateSessionResponse = response_json(second).await;
        assert!(second.replayed);
        assert_eq!(second.event, first.event);

        let sessions = app
            .clone()
            .oneshot(
                Request::get("/api/v1/sessions")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(sessions.status(), StatusCode::OK);
        let sessions: Vec<SessionSummary> = response_json(sessions).await;
        assert!(sessions.iter().any(|session| session.id == "session-api"));

        let detail = app
            .oneshot(
                Request::get("/api/v1/sessions/session-api")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(detail.status(), StatusCode::OK);
        let detail: SessionDetail = response_json(detail).await;
        assert_eq!(detail.session, first.session);
        assert_eq!(detail.events, vec![first.event]);
    }

    #[tokio::test]
    async fn session_list_is_a_bare_bounded_array_and_cursor_walks_101_rows() {
        let store = DemoStore::seeded().await.unwrap();
        let (app, current) = app_with_auth(store.clone()).await;
        for index in 0..100 {
            store
                .create_session_for_actor(
                    &current.authz,
                    CreateSessionRequest {
                        id: format!("session-page-{index:03}"),
                        title: format!("Pagination fixture {index:03}"),
                    },
                    &format!("create-page-{index:03}"),
                )
                .await
                .unwrap();
        }

        let first = app
            .clone()
            .oneshot(
                Request::get("/api/v1/sessions")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(first.status(), StatusCode::OK);
        let first_cursor = first
            .headers()
            .get("x-zeus-next-cursor")
            .expect("the first 50 rows must advertise a continuation cursor")
            .to_str()
            .unwrap()
            .to_owned();
        let first_json: serde_json::Value = response_json(first).await;
        assert!(
            first_json.is_array(),
            "the response contract is a bare array"
        );
        let first_page: Vec<SessionSummary> = serde_json::from_value(first_json).unwrap();
        assert_eq!(first_page.len(), 50);

        let second = app
            .clone()
            .oneshot(
                Request::get(format!("/api/v1/sessions?cursor={first_cursor}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(second.status(), StatusCode::OK);
        let second_cursor = second
            .headers()
            .get("x-zeus-next-cursor")
            .expect("the second 50 rows must advertise the last row")
            .to_str()
            .unwrap()
            .to_owned();
        let second_page: Vec<SessionSummary> = response_json(second).await;
        assert_eq!(second_page.len(), 50);

        let third = app
            .oneshot(
                Request::get(format!("/api/v1/sessions?cursor={second_cursor}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(third.status(), StatusCode::OK);
        assert!(third.headers().get("x-zeus-next-cursor").is_none());
        let third_page: Vec<SessionSummary> = response_json(third).await;
        assert_eq!(third_page.len(), 1);

        let ids = first_page
            .iter()
            .chain(&second_page)
            .chain(&third_page)
            .map(|session| session.id.as_str())
            .collect::<std::collections::HashSet<_>>();
        assert_eq!(ids.len(), 101, "cursor pages must not overlap or skip rows");
    }

    #[tokio::test]
    async fn session_list_rejects_invalid_limits_and_cursor_with_stable_problems() {
        let app = test_app().await;
        for uri in ["/api/v1/sessions?limit=0", "/api/v1/sessions?limit=101"] {
            let response = app
                .clone()
                .oneshot(Request::get(uri).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_problem(response, StatusCode::BAD_REQUEST, "invalid_page_limit").await;
        }

        let response = app
            .oneshot(
                Request::get("/api/v1/sessions?cursor=not-a-canonical-cursor")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_problem(response, StatusCode::BAD_REQUEST, "invalid_page_cursor").await;

        let future = ApiError::from(StoreError::PageCursorBeyondHead { head: 8 });
        assert_eq!(future.status, StatusCode::BAD_REQUEST);
        assert_eq!(future.problem.code, "invalid_page_cursor");
    }

    #[tokio::test]
    async fn session_detail_events_tail_pages_latest_first_but_returns_each_page_ascending() {
        let app = test_app().await;
        let latest = app
            .clone()
            .oneshot(
                Request::get("/api/v1/sessions/session-ZR-1842?events_limit=1")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(latest.status(), StatusCode::OK);
        let latest: SessionDetail = response_json(latest).await;
        assert_eq!(
            latest
                .events
                .iter()
                .map(|event| event.sequence)
                .collect::<Vec<_>>(),
            vec![2]
        );
        let latest_page = &latest.pagination.as_ref().unwrap().events;
        assert!(latest_page.has_more);
        let before = latest_page.next_before.as_deref().unwrap();

        let older = app
            .oneshot(
                Request::get(format!(
                    "/api/v1/sessions/session-ZR-1842?events_limit=1&events_before={before}"
                ))
                .body(Body::empty())
                .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(older.status(), StatusCode::OK);
        let older: SessionDetail = response_json(older).await;
        assert_eq!(
            older
                .events
                .iter()
                .map(|event| event.sequence)
                .collect::<Vec<_>>(),
            vec![1]
        );
        let older_page = &older.pagination.as_ref().unwrap().events;
        assert!(!older_page.has_more);
        assert!(older_page.next_before.is_none());
    }

    #[tokio::test]
    async fn session_turn_point_read_reaches_beyond_tail_and_masks_unknown_turns() {
        const SESSION_ID: &str = "session-ZR-1842";
        let store = DemoStore::seeded().await.unwrap();
        let (app, current) = app_with_auth(store.clone()).await;
        let mut sequence = 2;
        for ordinal in 1..=51 {
            let turn_id = format!("turn-point-{ordinal:03}");
            let started = store
                .start_turn_for_actor(
                    &current.authz,
                    SESSION_ID,
                    StartTurnRequest {
                        turn_id: turn_id.clone(),
                        user_message: format!("message {ordinal}"),
                        expected_sequence: sequence,
                    },
                    &format!("start-point-{ordinal:03}"),
                )
                .await
                .unwrap();
            let flushed = store
                .flush_turn_for_actor(
                    &current.authz,
                    SESSION_ID,
                    protocol::FlushSessionRequest {
                        turn_id,
                        assistant_message: Some(format!("answer {ordinal}")),
                        expected_sequence: started.session.sequence,
                    },
                    &format!("flush-point-{ordinal:03}"),
                )
                .await
                .unwrap();
            sequence = flushed.session.sequence;
        }

        let detail = app
            .clone()
            .oneshot(
                Request::get(format!("/api/v1/sessions/{SESSION_ID}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(detail.status(), StatusCode::OK);
        let detail: SessionDetail = response_json(detail).await;
        assert_eq!(detail.turns.len(), protocol::COLLECTION_PAGE_DEFAULT_LIMIT);
        assert!(detail.pagination.unwrap().turns.has_more);
        assert!(detail.turns.iter().all(|turn| turn.id != "turn-point-001"));

        let point = app
            .clone()
            .oneshot(
                Request::get(format!(
                    "/api/v1/sessions/{SESSION_ID}/turns/turn-point-001"
                ))
                .body(Body::empty())
                .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(point.status(), StatusCode::OK);
        let point: SessionTurn = response_json(point).await;
        assert_eq!(point.id, "turn-point-001");
        assert_eq!(point.status, protocol::SessionTurnStatus::Flushed);

        for turn_id in ["unknown-turn", "%20malformed-turn%20"] {
            let response = app
                .clone()
                .oneshot(
                    Request::get(format!("/api/v1/sessions/{SESSION_ID}/turns/{turn_id}"))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_problem(response, StatusCode::NOT_FOUND, "session_turn_not_found").await;
        }
    }

    #[tokio::test]
    async fn run_detail_events_tail_and_before_cursor_are_bounded_and_ascending() {
        let app = test_app().await;
        let latest = app
            .clone()
            .oneshot(
                Request::get(format!("/api/v1/runs/{DEMO_RUN_ID}?events_limit=2"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(latest.status(), StatusCode::OK);
        let latest: RunDetail = response_json(latest).await;
        assert_eq!(
            latest
                .events
                .iter()
                .map(|event| event.sequence)
                .collect::<Vec<_>>(),
            vec![7, 8]
        );
        let latest_page = &latest.pagination.as_ref().unwrap().events;
        assert!(latest_page.has_more);
        let before = latest_page.next_before.as_deref().unwrap();

        let older = app
            .oneshot(
                Request::get(format!(
                    "/api/v1/runs/{DEMO_RUN_ID}?events_limit=2&events_before={before}"
                ))
                .body(Body::empty())
                .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(older.status(), StatusCode::OK);
        let older: RunDetail = response_json(older).await;
        assert_eq!(
            older
                .events
                .iter()
                .map(|event| event.sequence)
                .collect::<Vec<_>>(),
            vec![5, 6]
        );
        let older_page = &older.pagination.as_ref().unwrap().events;
        assert!(older_page.has_more);
        assert!(older_page.next_before.is_some());
    }

    #[tokio::test]
    async fn session_create_rejects_missing_invalid_and_conflicting_idempotency_keys() {
        let app = test_app().await;
        let missing = app
            .clone()
            .oneshot(
                Request::post("/api/v1/sessions")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        r#"{"id":"session-missing-key","title":"Missing key"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(missing.status(), StatusCode::BAD_REQUEST);
        let problem: ProblemDetails = response_json(missing).await;
        assert_eq!(problem.code, "missing_idempotency_key");

        for invalid in [
            " key-with-spaces ".to_owned(),
            "x".repeat(protocol::IDEMPOTENCY_KEY_MAX_BYTES + 1),
        ] {
            let response = app
                .clone()
                .oneshot(
                    Request::post("/api/v1/sessions")
                        .header(header::CONTENT_TYPE, "application/json")
                        .header("idempotency-key", invalid)
                        .body(Body::from(
                            r#"{"id":"session-invalid-key","title":"Invalid key"}"#,
                        ))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_problem(response, StatusCode::BAD_REQUEST, "invalid_idempotency_key").await;
        }

        let duplicate = app
            .clone()
            .oneshot(
                Request::post("/api/v1/sessions")
                    .header(header::CONTENT_TYPE, "application/json")
                    .header("idempotency-key", "duplicate-one")
                    .header("idempotency-key", "duplicate-two")
                    .body(Body::from(
                        r#"{"id":"session-duplicate-key","title":"Duplicate key"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_problem(
            duplicate,
            StatusCode::BAD_REQUEST,
            "invalid_idempotency_key",
        )
        .await;

        let first = app
            .clone()
            .oneshot(
                Request::post("/api/v1/sessions")
                    .header(header::CONTENT_TYPE, "application/json")
                    .header("idempotency-key", "api-create-conflict")
                    .body(Body::from(
                        r#"{"id":"session-conflict","title":"Original"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(first.status(), StatusCode::CREATED);

        let conflict = app
            .oneshot(
                Request::post("/api/v1/sessions")
                    .header(header::CONTENT_TYPE, "application/json")
                    .header("idempotency-key", "api-create-conflict")
                    .body(Body::from(
                        r#"{"id":"session-conflict","title":"Different"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(conflict.status(), StatusCode::CONFLICT);
        let problem: ProblemDetails = response_json(conflict).await;
        assert_eq!(problem.code, "idempotency_conflict");
    }

    #[tokio::test]
    async fn session_errors_use_400_404_and_409_problem_details() {
        let app = test_app().await;

        let missing = app
            .clone()
            .oneshot(
                Request::get("/api/v1/sessions/not-real")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(missing.status(), StatusCode::NOT_FOUND);
        let problem: ProblemDetails = response_json(missing).await;
        assert_eq!(problem.code, "session_not_found");

        let invalid = app
            .clone()
            .oneshot(
                Request::post("/api/v1/sessions")
                    .header(header::CONTENT_TYPE, "application/json")
                    .header("idempotency-key", "api-create-invalid")
                    .body(Body::from(r#"{"id":" session-invalid","title":"Invalid"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(invalid.status(), StatusCode::BAD_REQUEST);
        let problem: ProblemDetails = response_json(invalid).await;
        assert_eq!(problem.code, "invalid_session_request");

        create_test_session(&app, "session-state").await;
        let duplicate = app
            .clone()
            .oneshot(
                Request::post("/api/v1/sessions")
                    .header(header::CONTENT_TYPE, "application/json")
                    .header("idempotency-key", "api-create-session-state-again")
                    .body(Body::from(r#"{"id":"session-state","title":"Duplicate"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(duplicate.status(), StatusCode::CONFLICT);
        let problem: ProblemDetails = response_json(duplicate).await;
        assert_eq!(problem.code, "session_already_exists");

        let started = app
            .clone()
            .oneshot(
                Request::post("/api/v1/sessions/session-state/turns")
                    .header(header::CONTENT_TYPE, "application/json")
                    .header("idempotency-key", "api-start-session-state")
                    .body(Body::from(
                        r#"{"turn_id":"turn-state","user_message":"Keep running","expected_sequence":1}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(started.status(), StatusCode::OK);

        let invalid_transition = app
            .oneshot(
                Request::post("/api/v1/sessions/session-state/resume")
                    .header(header::CONTENT_TYPE, "application/json")
                    .header("idempotency-key", "api-resume-running-session")
                    .body(Body::from(r#"{"expected_sequence":2}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(invalid_transition.status(), StatusCode::CONFLICT);
        let problem: ProblemDetails = response_json(invalid_transition).await;
        assert_eq!(problem.code, "invalid_session_transition");
        assert_eq!(
            problem.detail,
            "The session state does not allow this command"
        );
    }

    #[tokio::test]
    async fn start_and_flush_routes_are_idempotent_and_validate_the_path_turn() {
        let app = test_app().await;
        create_test_session(&app, "session-turns").await;

        let start_request = || {
            Request::post("/api/v1/sessions/session-turns/turns")
                .header(header::CONTENT_TYPE, "application/json")
                .header("idempotency-key", "api-start-turn-1")
                .body(Body::from(
                    r#"{"turn_id":"turn-1","user_message":"Investigate","expected_sequence":1}"#,
                ))
                .unwrap()
        };
        let started = app.clone().oneshot(start_request()).await.unwrap();
        assert_eq!(started.status(), StatusCode::OK);
        let started: StartTurnResponse = response_json(started).await;
        assert!(!started.replayed);
        assert_eq!(started.session.status, SessionStatus::Running);
        assert_eq!(started.session.sequence, 2);

        let replayed = app.clone().oneshot(start_request()).await.unwrap();
        assert_eq!(replayed.status(), StatusCode::OK);
        let replayed: StartTurnResponse = response_json(replayed).await;
        assert!(replayed.replayed);
        assert_eq!(replayed.event, started.event);

        let mismatch = app
            .clone()
            .oneshot(
                Request::post("/api/v1/sessions/session-turns/turns/not-turn-1/flush")
                    .header(header::CONTENT_TYPE, "application/json")
                    .header("idempotency-key", "api-flush-mismatch")
                    .body(Body::from(
                        r#"{"turn_id":"turn-1","assistant_message":"Done","expected_sequence":2}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(mismatch.status(), StatusCode::BAD_REQUEST);
        let problem: ProblemDetails = response_json(mismatch).await;
        assert_eq!(problem.code, "turn_id_mismatch");

        let unchanged = app
            .clone()
            .oneshot(
                Request::get("/api/v1/sessions/session-turns")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let unchanged: SessionDetail = response_json(unchanged).await;
        assert_eq!(unchanged.session.status, SessionStatus::Running);
        assert_eq!(unchanged.session.sequence, 2);

        let flush_request = || {
            Request::post("/api/v1/sessions/session-turns/turns/turn-1/flush")
                .header(header::CONTENT_TYPE, "application/json")
                .header("idempotency-key", "api-flush-turn-1")
                .body(Body::from(
                    r#"{"turn_id":"turn-1","assistant_message":"Done","expected_sequence":2}"#,
                ))
                .unwrap()
        };
        let flushed = app.clone().oneshot(flush_request()).await.unwrap();
        assert_eq!(flushed.status(), StatusCode::OK);
        let flushed: FlushSessionResponse = response_json(flushed).await;
        assert!(!flushed.replayed);
        assert_eq!(flushed.session.status, SessionStatus::Ready);
        assert_eq!(flushed.ack.turn_id, "turn-1");
        assert_eq!(flushed.ack.durability_sequence, 4);

        let replayed = app.oneshot(flush_request()).await.unwrap();
        assert_eq!(replayed.status(), StatusCode::OK);
        let replayed: FlushSessionResponse = response_json(replayed).await;
        assert!(replayed.replayed);
        assert_eq!(replayed.ack, flushed.ack);
        assert_eq!(replayed.events, flushed.events);
    }

    #[tokio::test]
    async fn session_flush_barrier_is_server_owned_bounded_and_no_store() {
        let app = test_app().await;
        create_test_session(&app, "session-flush-barrier").await;

        let ready = app
            .clone()
            .oneshot(
                Request::post("/api/v1/sessions/session-flush-barrier/flush?timeout_ms=0")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(ready.status(), StatusCode::OK);
        assert_eq!(
            ready.headers().get(header::CACHE_CONTROL),
            Some(&HeaderValue::from_static("no-store"))
        );
        let ready: SessionFlushBarrier = response_json(ready).await;
        assert_eq!(ready.status, SessionFlushBarrierStatus::Quiescent);
        assert_eq!(ready.through_sequence, 1);
        assert_eq!(ready.through_followup_ordinal, 0);

        let started = app
            .clone()
            .oneshot(
                Request::post("/api/v1/sessions/session-flush-barrier/turns")
                    .header(header::CONTENT_TYPE, "application/json")
                    .header("idempotency-key", "start-session-flush-barrier")
                    .body(Body::from(
                        r#"{"turn_id":"turn-flush-barrier","user_message":"Remain open","expected_sequence":1}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(started.status(), StatusCode::OK);

        let pending = app
            .clone()
            .oneshot(
                Request::post("/api/v1/sessions/session-flush-barrier/flush?timeout_ms=0")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(pending.status(), StatusCode::ACCEPTED);
        assert_eq!(
            pending.headers().get(header::RETRY_AFTER),
            Some(&HeaderValue::from_static("1"))
        );
        assert_eq!(
            pending.headers().get(header::CACHE_CONTROL),
            Some(&HeaderValue::from_static("no-store"))
        );
        let pending: SessionFlushBarrier = response_json(pending).await;
        assert_eq!(pending.status, SessionFlushBarrierStatus::Pending);
        assert_eq!(
            pending.active_turn_id.as_deref(),
            Some("turn-flush-barrier")
        );

        let invalid = app
            .clone()
            .oneshot(
                Request::post("/api/v1/sessions/session-flush-barrier/flush?timeout_ms=30001")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(invalid.status(), StatusCode::BAD_REQUEST);
        let problem: ProblemDetails = response_json(invalid).await;
        assert_eq!(problem.code, "invalid_session_flush_timeout");

        let flushed = app
            .clone()
            .oneshot(
                Request::post(
                    "/api/v1/sessions/session-flush-barrier/turns/turn-flush-barrier/flush",
                )
                .header(header::CONTENT_TYPE, "application/json")
                .header("idempotency-key", "finish-session-flush-barrier")
                .body(Body::from(
                    r#"{"turn_id":"turn-flush-barrier","assistant_message":"Done","expected_sequence":2}"#,
                ))
                .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(flushed.status(), StatusCode::OK);

        let settled = app
            .oneshot(
                Request::post("/api/v1/sessions/session-flush-barrier/flush?timeout_ms=0")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(settled.status(), StatusCode::OK);
        let settled: SessionFlushBarrier = response_json(settled).await;
        assert_eq!(settled.status, SessionFlushBarrierStatus::Quiescent);
        assert_eq!(settled.observed_sequence, 4);
    }

    #[tokio::test]
    async fn session_sse_replays_events_after_the_cursor() {
        let app = test_app().await;
        create_test_session(&app, "session-events").await;
        let started = app
            .clone()
            .oneshot(
                Request::post("/api/v1/sessions/session-events/turns")
                    .header(header::CONTENT_TYPE, "application/json")
                    .header("idempotency-key", "api-start-events")
                    .body(Body::from(
                        r#"{"turn_id":"turn-events","user_message":"Stream me","expected_sequence":1}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(started.status(), StatusCode::OK);

        let response = app
            .oneshot(
                Request::get("/api/v1/sessions/session-events/events?after=1")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert!(
            response.headers()[header::CONTENT_TYPE]
                .to_str()
                .unwrap()
                .starts_with("text/event-stream")
        );
        let frame = tokio::time::timeout(Duration::from_secs(1), response.into_body().frame())
            .await
            .expect("session SSE replay should be immediate")
            .expect("session SSE stream should produce a frame")
            .expect("session SSE frame should be valid");
        let payload = String::from_utf8(frame.into_data().unwrap().to_vec()).unwrap();
        assert!(payload.contains("event: session.event"));
        assert!(payload.contains("id: 2"));
        assert!(!payload.contains("id: 1"));
    }

    #[tokio::test]
    async fn session_sse_replays_multiple_bounded_pages_without_waiting_for_poll() {
        let store = DemoStore::seeded().await.unwrap();
        let app = app_with_event_feed_options(store, Duration::from_secs(30), true).await;
        let session_id = "session-multi-page-replay";
        create_test_session(&app, session_id).await;

        let mut sequence = 1u64;
        for index in 0..43 {
            let turn_id = format!("turn-page-{index}");
            let started = app
                .clone()
                .oneshot(
                    Request::post(format!("/api/v1/sessions/{session_id}/turns"))
                        .header(header::CONTENT_TYPE, "application/json")
                        .header("idempotency-key", format!("start-page-{index}"))
                        .body(Body::from(
                            serde_json::json!({
                                "turn_id": turn_id,
                                "user_message": format!("page message {index}"),
                                "expected_sequence": sequence,
                            })
                            .to_string(),
                        ))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(started.status(), StatusCode::OK);
            let started: StartTurnResponse = response_json(started).await;
            sequence = started.session.sequence;

            let flushed = app
                .clone()
                .oneshot(
                    Request::post(format!(
                        "/api/v1/sessions/{session_id}/turns/{turn_id}/flush"
                    ))
                    .header(header::CONTENT_TYPE, "application/json")
                    .header("idempotency-key", format!("flush-page-{index}"))
                    .body(Body::from(
                        serde_json::json!({
                            "turn_id": turn_id,
                            "assistant_message": format!("page reply {index}"),
                            "expected_sequence": sequence,
                        })
                        .to_string(),
                    ))
                    .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(flushed.status(), StatusCode::OK);
            let flushed: FlushSessionResponse = response_json(flushed).await;
            sequence = flushed.session.sequence;
        }
        assert_eq!(sequence, 130);

        let response = app
            .oneshot(
                Request::get(format!("/api/v1/sessions/{session_id}/events?after=0"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let mut body = response.into_body();
        let sequences = tokio::time::timeout(Duration::from_secs(2), async {
            let mut sequences = Vec::new();
            while sequences.last().copied() != Some(sequence) {
                let frame = body
                    .frame()
                    .await
                    .expect("the paged replay must remain open")
                    .expect("the paged replay frame must be valid");
                let Ok(data) = frame.into_data() else {
                    continue;
                };
                let payload = String::from_utf8(data.to_vec()).unwrap();
                sequences.extend(payload.lines().filter_map(|line| {
                    line.strip_prefix("id: ")
                        .map(|value| value.parse::<u64>().unwrap())
                }));
            }
            sequences
        })
        .await
        .expect("the second event page must not wait for the 30-second poll");
        assert_eq!(sequences, (1..=sequence).collect::<Vec<_>>());
    }

    #[tokio::test]
    async fn sse_replays_only_events_after_the_cursor() {
        let response = test_app()
            .await
            .oneshot(
                Request::get(format!("/api/v1/runs/{DEMO_RUN_ID}/events?after=4"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert!(
            response.headers()[header::CONTENT_TYPE]
                .to_str()
                .unwrap()
                .starts_with("text/event-stream")
        );
        let frame = tokio::time::timeout(Duration::from_secs(1), response.into_body().frame())
            .await
            .expect("SSE replay should be immediate")
            .expect("SSE stream should produce a frame")
            .expect("SSE frame should be valid");
        let payload = String::from_utf8(frame.into_data().unwrap().to_vec()).unwrap();
        assert!(payload.contains("id: 5"));
        assert!(!payload.contains("id: 4"));
    }

    #[tokio::test]
    async fn sse_reconnect_prefers_last_event_id_over_initial_query() {
        let response = test_app()
            .await
            .oneshot(
                Request::get(format!("/api/v1/runs/{DEMO_RUN_ID}/events?after=1"))
                    .header("last-event-id", "4")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        let frame = tokio::time::timeout(Duration::from_secs(1), response.into_body().frame())
            .await
            .expect("SSE replay should be immediate")
            .expect("SSE stream should produce a frame")
            .expect("SSE frame should be valid");
        let payload = String::from_utf8(frame.into_data().unwrap().to_vec()).unwrap();
        assert!(payload.contains("id: 5"));
        assert!(!payload.contains("id: 2"));
    }

    #[test]
    fn event_cursor_rejects_duplicate_malformed_or_out_of_range_values() {
        let mut duplicate = HeaderMap::new();
        duplicate.append("last-event-id", HeaderValue::from_static("1"));
        duplicate.append("last-event-id", HeaderValue::from_static("2"));
        let duplicate_error = event_cursor(&duplicate, EventsQuery::default()).unwrap_err();
        assert_eq!(duplicate_error.status, StatusCode::BAD_REQUEST);
        assert_eq!(duplicate_error.problem.code, "invalid_event_cursor");

        for malformed in ["", "-1", "not-a-sequence"] {
            let mut headers = HeaderMap::new();
            headers.insert("last-event-id", HeaderValue::from_str(malformed).unwrap());
            let error = event_cursor(&headers, EventsQuery::default()).unwrap_err();
            assert_eq!(error.status, StatusCode::BAD_REQUEST);
            assert_eq!(error.problem.code, "invalid_event_cursor");
        }
        let mut non_utf8 = HeaderMap::new();
        non_utf8.insert("last-event-id", HeaderValue::from_bytes(&[0xff]).unwrap());
        let non_utf8_error = event_cursor(&non_utf8, EventsQuery::default()).unwrap_err();
        assert_eq!(non_utf8_error.status, StatusCode::BAD_REQUEST);
        assert_eq!(non_utf8_error.problem.code, "invalid_event_cursor");

        let out_of_range = (i64::MAX as u64 + 1).to_string();
        let mut header = HeaderMap::new();
        header.insert(
            "last-event-id",
            HeaderValue::from_str(&out_of_range).unwrap(),
        );
        let header_error = event_cursor(&header, EventsQuery::default()).unwrap_err();
        assert_eq!(header_error.status, StatusCode::BAD_REQUEST);
        assert_eq!(header_error.problem.code, "invalid_event_cursor");

        let query_error = event_cursor(
            &HeaderMap::new(),
            EventsQuery {
                after: Some(i64::MAX as u64 + 1),
            },
        )
        .unwrap_err();
        assert_eq!(query_error.status, StatusCode::BAD_REQUEST);
        assert_eq!(query_error.problem.code, "invalid_event_cursor");
    }

    #[tokio::test]
    async fn owned_future_event_cursors_are_rejected_before_sse_opens() {
        let app = test_app().await;
        for uri in [
            "/api/v1/sessions/session-ZR-1842/events?after=3".to_owned(),
            format!("/api/v1/runs/{DEMO_RUN_ID}/events?after=9"),
        ] {
            let response = app
                .clone()
                .oneshot(Request::get(uri).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_problem(response, StatusCode::CONFLICT, "event_cursor_beyond_head").await;
        }
    }

    #[tokio::test]
    async fn sse_polls_the_ledger_without_local_broadcast_hints() {
        let store = DemoStore::seeded().await.unwrap();
        let (app, current) =
            app_with_event_feed_options_and_auth(store.clone(), Duration::from_millis(10), false)
                .await;
        let response = app
            .oneshot(
                Request::get(format!("/api/v1/runs/{DEMO_RUN_ID}/events?after=8"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        // Start polling before the commit. Broadcast hints are disabled for
        // this test route, so only the durable sequence cursor can advance the
        // stream.
        let mut body = response.into_body();
        let opened = tokio::time::timeout(Duration::from_secs(1), body.frame())
            .await
            .expect("SSE should flush its opening comment immediately")
            .expect("SSE stream should produce an opening frame")
            .expect("SSE opening frame should be valid");
        let opened = String::from_utf8(opened.into_data().unwrap().to_vec()).unwrap();
        assert!(opened.contains(": stream-open"));

        let next_frame = tokio::spawn(async move {
            tokio::time::timeout(Duration::from_secs(2), body.frame())
                .await
                .expect("SSE durable polling should observe the commit")
                .expect("SSE stream should produce a frame")
                .expect("SSE frame should be valid")
        });
        tokio::time::sleep(Duration::from_millis(30)).await;

        let reviewed = store
            .review_for_actor(
                &current.authz,
                DEMO_RUN_ID,
                "APR-901",
                ReviewRequest {
                    decision: ReviewDecision::Reject,
                    note: Some("durable poll review".into()),
                    idempotency_key: None,
                },
                "durable-poll-review-1",
            )
            .await
            .unwrap();
        assert_eq!(reviewed.event.sequence, 9);

        let frame = next_frame.await.unwrap();
        let payload = String::from_utf8(frame.into_data().unwrap().to_vec()).unwrap();
        assert!(payload.contains("id: 9"));
        assert!(payload.contains("approval_decided"));
        assert!(!payload.contains("id: 8"));
    }

    #[tokio::test]
    async fn run_broadcast_hint_reconciles_every_durable_event_before_it() {
        let store = DemoStore::seeded().await.unwrap();
        let current = configure_test_actor(&store).await;
        let reviewed = store
            .review_for_actor(
                &current.authz,
                DEMO_RUN_ID,
                "APR-901",
                ReviewRequest {
                    decision: ReviewDecision::Approve,
                    note: Some("exercise ordered hint reconciliation".into()),
                    idempotency_key: None,
                },
                "ordered-run-hint-review-1",
            )
            .await
            .unwrap();
        assert_eq!(reviewed.event.sequence, 9);

        let detail = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let detail = store
                    .run_detail_for_actor(
                        &current.authz,
                        DEMO_RUN_ID,
                        None,
                        protocol::EVENT_PAGE_DEFAULT_LIMIT,
                    )
                    .await
                    .unwrap();
                if detail.run.sequence >= 10 {
                    break detail;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("the guarded demo dispatcher should settle durably");
        let hinted = detail.events.last().cloned().unwrap();
        assert_eq!(hinted.sequence, 10);
        assert!(matches!(
            &hinted.data,
            Some(protocol::RunEventData::ToolResult {
                status: protocol::ToolCallStatus::NotDispatched,
                ..
            })
        ));

        let replay = run_events_for_hint(
            &store,
            &current.authz,
            DEMO_RUN_ID,
            8,
            &PublishedEvent {
                run_id: DEMO_RUN_ID.into(),
                event: hinted,
            },
        )
        .await
        .unwrap()
        .expect("a newer matching hint must trigger one durable page");
        assert!(!replay.has_more);
        assert_eq!(
            replay
                .items
                .iter()
                .map(|event| event.sequence)
                .collect::<Vec<_>>(),
            vec![9, 10]
        );
    }

    #[tokio::test]
    async fn internal_execution_invariants_return_a_generic_500_problem() {
        let errors = [
            StoreError::ToolCallNotFound,
            StoreError::ExecutionInvariant("private persisted binding detail".into()),
            StoreError::Kernel(kernel::KernelError::InvalidToolCall),
            StoreError::SequenceOverflow,
        ];

        for error in errors {
            let response = ApiError::from(error).into_response();
            assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
            let problem: ProblemDetails = response_json(response).await;
            assert_eq!(problem.code, "runtime_unavailable");
            assert_eq!(problem.title, "Runtime is unavailable");
            assert_eq!(
                problem.detail,
                "The runtime could not process the request safely"
            );
            assert!(!problem.detail.contains("binding"));
            assert!(!problem.detail.contains("tool call"));
        }
    }

    #[tokio::test]
    async fn durable_capacity_errors_use_stable_429_contracts() {
        for (error, code, retry_after) in [
            (
                StoreError::StorageQuotaExceeded,
                "storage_quota_exceeded",
                None,
            ),
            (
                StoreError::ReplyQueueCapacityExceeded,
                "reply_queue_capacity_exceeded",
                Some("2"),
            ),
            (
                StoreError::DispatchQueueCapacityExceeded,
                "dispatch_queue_capacity_exceeded",
                Some("2"),
            ),
            (
                StoreError::AuthSessionCapacityExceeded,
                "auth_session_capacity_exceeded",
                None,
            ),
        ] {
            let response = ApiError::from(error).into_response();
            assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
            assert_eq!(
                response.headers().get(header::CACHE_CONTROL).unwrap(),
                "no-store"
            );
            assert_eq!(
                response
                    .headers()
                    .get(header::RETRY_AFTER)
                    .and_then(|value| value.to_str().ok()),
                retry_after
            );
            let problem: ProblemDetails = response_json(response).await;
            assert_eq!(problem.code, code);
        }
    }

    #[tokio::test]
    async fn authorization_errors_use_stable_no_store_contracts() {
        for (error, status, code) in [
            (
                StoreError::AuthSessionNotFound,
                StatusCode::UNAUTHORIZED,
                "authentication_required",
            ),
            (
                StoreError::PermissionDenied,
                StatusCode::FORBIDDEN,
                "permission_denied",
            ),
        ] {
            let response = ApiError::from(error).into_response();
            assert_eq!(response.status(), status);
            assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
            let problem: ProblemDetails = response_json(response).await;
            assert_eq!(problem.code, code);
        }
    }

    #[tokio::test]
    async fn member_and_audit_errors_use_stable_concealment_and_capacity_contracts() {
        for (error, status, code) in [
            (
                StoreError::MemberNotFound("foreign-or-missing".into()),
                StatusCode::NOT_FOUND,
                "member_not_found",
            ),
            (
                StoreError::MembershipRevisionConflict,
                StatusCode::CONFLICT,
                "membership_revision_conflict",
            ),
            (
                StoreError::LastAccountOwner,
                StatusCode::CONFLICT,
                "last_account_owner",
            ),
            (
                StoreError::AuditStorageExhausted,
                StatusCode::INSUFFICIENT_STORAGE,
                "audit_storage_exhausted",
            ),
            (
                StoreError::AuditLegalHold,
                StatusCode::INSUFFICIENT_STORAGE,
                "audit_storage_exhausted",
            ),
            (
                StoreError::AuditArchiveRequired,
                StatusCode::INSUFFICIENT_STORAGE,
                "audit_storage_exhausted",
            ),
            (
                StoreError::AuditPolicyConflict,
                StatusCode::CONFLICT,
                "audit_policy_revision_conflict",
            ),
            (
                StoreError::AuditCheckpointConflict,
                StatusCode::CONFLICT,
                "audit_checkpoint_conflict",
            ),
        ] {
            let response = ApiError::from(error).into_response();
            assert_eq!(response.status(), status);
            assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
            let problem: ProblemDetails = response_json(response).await;
            assert_eq!(problem.code, code);
        }

        let mut expected = None;
        for error in [
            StoreError::InvalidMemberSetupToken,
            StoreError::MemberSetupExpired,
            StoreError::MemberSetupAlreadyCompleted,
        ] {
            let response = ApiError::from(error).into_response();
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
            assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
            let problem: ProblemDetails = response_json(response).await;
            assert_eq!(problem.code, "invalid_member_setup_token");
            if let Some(expected) = &expected {
                assert_eq!(&problem, expected);
            } else {
                expected = Some(problem);
            }
        }
    }

    #[tokio::test]
    async fn physical_capacity_errors_use_a_stable_507_contract() {
        let response = ApiError::from(StoreError::PhysicalStorageExhausted).into_response();
        assert_eq!(response.status(), StatusCode::INSUFFICIENT_STORAGE);
        assert_eq!(
            response.headers().get(header::CACHE_CONTROL).unwrap(),
            "no-store"
        );
        let problem: ProblemDetails = response_json(response).await;
        assert_eq!(problem.code, "physical_storage_exhausted");
        assert_eq!(problem.title, "Physical storage capacity exhausted");
        assert!(!problem.detail.contains("bytes"));
        assert!(!problem.detail.contains("path"));
    }

    #[tokio::test]
    async fn sqlite_operation_capacity_uses_a_stable_retryable_503_contract() {
        let response = ApiError::from(StoreError::OperationCapacityExceeded).into_response();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            response.headers().get(header::CACHE_CONTROL).unwrap(),
            "no-store"
        );
        assert_eq!(response.headers().get(header::RETRY_AFTER).unwrap(), "1");
        let problem: ProblemDetails = response_json(response).await;
        assert_eq!(problem.code, "sqlite_operation_capacity_exceeded");
        assert_eq!(problem.title, "SQLite operation capacity exceeded");
        assert!(!problem.detail.contains("permit"));
        assert!(!problem.detail.contains("timeout"));
    }

    #[tokio::test]
    async fn missing_finalization_reservation_is_sanitized_and_not_cached() {
        let response =
            ApiError::from(StoreError::FinalizationReservationUnavailable).into_response();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            response.headers().get(header::CACHE_CONTROL).unwrap(),
            "no-store"
        );
        let problem: ProblemDetails = response_json(response).await;
        assert_eq!(problem.code, "runtime_unavailable");
        assert!(!problem.detail.contains("reservation"));
    }

    #[tokio::test]
    async fn unknown_runs_use_problem_details() {
        let response = test_app()
            .await
            .oneshot(
                Request::get("/api/v1/runs/not-real")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_eq!(
            response.headers()[header::CONTENT_TYPE],
            "application/problem+json"
        );
        let problem: ProblemDetails = response_json(response).await;
        assert_eq!(problem.code, "run_not_found");
    }

    #[tokio::test]
    async fn review_requires_an_idempotency_header() {
        let response = test_app()
            .await
            .oneshot(
                Request::post(format!(
                    "/api/v1/runs/{DEMO_RUN_ID}/approvals/APR-901/decision"
                ))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"decision":"approve"}"#))
                .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let problem: ProblemDetails = response_json(response).await;
        assert_eq!(problem.code, "missing_idempotency_key");
    }

    const TEST_OWNER_PASSWORD: &str = "Owner-password-2026";

    struct ConfiguredAuthFixture {
        app: Router,
        store: DemoStore,
        auth: Arc<AuthConfig>,
        path: PathBuf,
    }

    impl ConfiguredAuthFixture {
        fn cleanup(self) {
            let Self {
                app,
                store,
                auth,
                path,
            } = self;
            drop(app);
            drop(auth);
            drop(store);
            cleanup_test_database(&path);
        }
    }

    async fn configured_auth_test_app(
        label: &str,
        login_policy: RateLimitPolicy,
    ) -> ConfiguredAuthFixture {
        configured_auth_test_app_with_ingress(label, login_policy, IngressPolicy::direct(false))
            .await
    }

    async fn configured_auth_test_app_with_ingress(
        label: &str,
        login_policy: RateLimitPolicy,
        ingress: IngressPolicy,
    ) -> ConfiguredAuthFixture {
        let unique = UserId::generate().unwrap();
        let path = std::env::temp_dir().join(format!(
            "zeus-api-{label}-{}.db",
            unique.as_str().replace(':', "-")
        ));
        let store = DemoStore::open(&path).await.unwrap();
        let bootstrap_token = BootstrapToken::generate().unwrap();
        let expires_at = (chrono::Utc::now() + chrono::Duration::minutes(15))
            .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        store
            .replace_bootstrap_token(&bootstrap_token.digest().to_persistence(), &expires_at)
            .await
            .unwrap();

        let bootstrap_origin = ingress
            .public_origin()
            .unwrap_or("http://zeus.test")
            .to_owned();
        let bootstrap_forwarded = ingress.public_origin().map(|origin| {
            format!(
                "for=198.51.100.1;proto=https;host={}",
                origin
                    .strip_prefix("https://")
                    .expect("trusted ingress test origin must use HTTPS")
            )
        });

        let clock = ManualRateLimitClock::new();
        let rate_clock: Arc<dyn RateLimitClock> = clock;
        let auth = Arc::new(AuthConfig {
            authenticator: Arc::new(PasswordAuthenticator::new().unwrap()),
            password_workers: Arc::new(Semaphore::new(PASSWORD_WORKER_LIMIT)),
            rate_limits: AuthRateLimits::with_policies(
                rate_clock,
                login_policy,
                BOOTSTRAP_RATE_POLICY,
            ),
            ingress,
        });
        let state = ApiState {
            store: store.clone(),
            durable_ledger_poll_interval: DURABLE_LEDGER_POLL_INTERVAL,
            broadcast_hints_enabled: true,
            auth: Some(Arc::clone(&auth)),
            reply: Some(Arc::new(ReplyExecutor::new(Arc::new(
                LocalFallbackProvider::new(),
            )))),
            sse_capacity: SseCapacity::production(),
        };
        let app = build_authenticated_app(state).layer(MockConnectInfo(test_peer()));
        let mut bootstrap_request = Request::post("/api/v1/auth/bootstrap")
            .header(header::HOST, "zeus.test")
            .header(header::ORIGIN, &bootstrap_origin)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(
                serde_json::json!({
                    "bootstrap_token": bootstrap_token.expose_secret(),
                    "username": "owner",
                    "password": TEST_OWNER_PASSWORD,
                })
                .to_string(),
            ))
            .unwrap();
        if let Some(forwarded) = bootstrap_forwarded {
            bootstrap_request.headers_mut().insert(
                header::FORWARDED,
                HeaderValue::from_str(&forwarded).unwrap(),
            );
        }
        let bootstrap = app.clone().oneshot(bootstrap_request).await.unwrap();
        assert_eq!(bootstrap.status(), StatusCode::OK);

        ConfiguredAuthFixture {
            app,
            store,
            auth,
            path,
        }
    }

    fn login_request(username: &str, password: &str) -> Request<Body> {
        Request::post("/api/v1/auth/login")
            .header(header::HOST, "zeus.test")
            .header(header::ORIGIN, "http://zeus.test")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(
                serde_json::json!({
                    "username": username,
                    "password": password,
                })
                .to_string(),
            ))
            .unwrap()
    }

    fn member_setup_request(path: &str, setup_token: &str, password: &str) -> Request<Body> {
        Request::post(path)
            .header(header::HOST, "zeus.test")
            .header(header::ORIGIN, "http://zeus.test")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(
                serde_json::json!({
                    "setup_token": setup_token,
                    "password": password,
                })
                .to_string(),
            ))
            .unwrap()
    }

    fn bootstrap_request(bootstrap_token: &str) -> Request<Body> {
        Request::post("/api/v1/auth/bootstrap")
            .header(header::HOST, "zeus.test")
            .header(header::ORIGIN, "http://zeus.test")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(
                serde_json::json!({
                    "bootstrap_token": bootstrap_token,
                    "username": "owner",
                    "password": TEST_OWNER_PASSWORD,
                })
                .to_string(),
            ))
            .unwrap()
    }

    fn update_test_user_status(path: &Path, status: &str) {
        let connection = Connection::open(path).unwrap();
        connection.busy_timeout(Duration::from_secs(1)).unwrap();
        assert_eq!(
            connection
                .execute(
                    "UPDATE users SET status = ?1, updated_at = ?2 WHERE username = 'owner'",
                    params![
                        status,
                        chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
                    ],
                )
                .unwrap(),
            1
        );
    }

    fn copy_test_password(path: &Path, source_username: &str, target_username: &str) {
        let connection = Connection::open(path).unwrap();
        connection.busy_timeout(Duration::from_secs(1)).unwrap();
        assert_eq!(
            connection
                .execute(
                    r#"UPDATE users
                       SET password_hash = (
                               SELECT password_hash FROM users WHERE username = ?1
                           ),
                           updated_at = ?3
                       WHERE username = ?2"#,
                    params![
                        source_username,
                        target_username,
                        chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
                    ],
                )
                .unwrap(),
            1
        );
    }

    fn insert_test_non_local_owner(path: &Path) {
        let connection = Connection::open(path).unwrap();
        connection.busy_timeout(Duration::from_secs(1)).unwrap();
        connection
            .pragma_update(None, "foreign_keys", "ON")
            .unwrap();
        let timestamp = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        connection
            .execute(
                r#"INSERT INTO accounts(id, name, status, created_at, updated_at)
                   VALUES ('acc_other', 'Other', 'active', ?1, ?1)"#,
                [&timestamp],
            )
            .unwrap();
        connection
            .execute(
                r#"INSERT INTO users(
                       id, username, role, status, password_hash, created_at, updated_at
                   ) VALUES (
                       'user-other-owner', 'other-owner', 'owner', 'active',
                       '$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$ZGlnaWVzdA', ?1, ?1
                   )"#,
                [&timestamp],
            )
            .unwrap();
        connection
            .execute(
                r#"INSERT INTO account_memberships(
                       account_id, user_id, role, status, revision, created_at, updated_at
                   ) VALUES (
                       'acc_other', 'user-other-owner', 'owner', 'active', 1, ?1, ?1
                   )"#,
                [&timestamp],
            )
            .unwrap();
    }

    fn insert_test_disabled_local_owner(path: &Path) {
        let connection = Connection::open(path).unwrap();
        connection.busy_timeout(Duration::from_secs(1)).unwrap();
        connection
            .pragma_update(None, "foreign_keys", "ON")
            .unwrap();
        let timestamp = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        connection
            .execute(
                r#"INSERT INTO users(
                       id, username, role, status, password_hash, created_at, updated_at
                   ) VALUES (
                       'user-disabled-owner', 'disabled-owner', 'owner', 'active',
                       '$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$ZGlnaWVzdA', ?1, ?1
                   )"#,
                [&timestamp],
            )
            .unwrap();
        connection
            .execute(
                r#"INSERT INTO account_memberships(
                       account_id, user_id, role, status, revision, created_at, updated_at
                   ) VALUES (
                       'acc_local', 'user-disabled-owner', 'owner', 'disabled', 1, ?1, ?1
                   )"#,
                [&timestamp],
            )
            .unwrap();
    }

    async fn assert_problem(response: Response, status: StatusCode, code: &str) {
        assert_eq!(response.status(), status);
        assert_eq!(
            response.headers()[header::CONTENT_TYPE],
            "application/problem+json"
        );
        let problem: ProblemDetails = response_json(response).await;
        assert_eq!(problem.status, status.as_u16());
        assert_eq!(problem.code, code);
    }

    fn test_peer() -> SocketAddr {
        "127.0.0.1:41000".parse().unwrap()
    }

    struct TestIdentity {
        user_id: String,
        authz: AuthzContext,
        cookie_header: String,
        csrf_token: String,
    }

    async fn approve_agent_tool(
        app: &Router,
        identity: &TestIdentity,
        session_id: &str,
        turn_id: &str,
        call_id: &str,
        idempotency_key: &str,
    ) -> AgentReviewResponse {
        let response = app
            .clone()
            .oneshot(
                Request::post(format!(
                    "/api/v1/sessions/{session_id}/turns/{turn_id}/approvals/{call_id}/decision"
                ))
                .header(header::HOST, "zeus.test")
                .header(header::ORIGIN, "http://zeus.test")
                .header(header::COOKIE, &identity.cookie_header)
                .header(CSRF_HEADER, &identity.csrf_token)
                .header(header::CONTENT_TYPE, "application/json")
                .header("idempotency-key", idempotency_key)
                .body(Body::from(
                    serde_json::json!({
                        "decision": "approve",
                        "note": "approve the exact persisted isolated terminal operation",
                        "idempotency_key": idempotency_key,
                    })
                    .to_string(),
                ))
                .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        response_json(response).await
    }

    async fn authenticated_file_app(label: &str) -> (Router, DemoStore, TestIdentity, PathBuf) {
        let unique = UserId::generate().unwrap();
        let path = std::env::temp_dir().join(format!(
            "zeus-api-{label}-{}.db",
            unique.as_str().replace(':', "-")
        ));
        let store = DemoStore::open(&path).await.unwrap();
        let identity = provision_test_owner(&store, "user-alice", "alice").await;
        let app = authenticated_app(store.clone(), false).unwrap();
        (app, store, identity, path)
    }

    async fn wait_for_ready_session(
        store: &DemoStore,
        authz: &AuthzContext,
        session_id: &str,
    ) -> SessionDetail {
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let detail = store
                    .get_session_for_actor(
                        authz,
                        session_id,
                        None,
                        protocol::COLLECTION_PAGE_DEFAULT_LIMIT,
                        None,
                        protocol::COLLECTION_PAGE_DEFAULT_LIMIT,
                        None,
                        protocol::EVENT_PAGE_DEFAULT_LIMIT,
                    )
                    .await
                    .unwrap();
                if detail.session.status == SessionStatus::Ready {
                    break detail;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("the durable assistant reply should settle")
    }

    async fn wait_for_session_state_and_turns(
        store: &DemoStore,
        authz: &AuthzContext,
        session_id: &str,
        status: SessionStatus,
        minimum_turns: usize,
    ) -> SessionDetail {
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let detail = store
                    .get_session_for_actor(
                        authz,
                        session_id,
                        None,
                        protocol::COLLECTION_PAGE_DEFAULT_LIMIT,
                        None,
                        protocol::COLLECTION_PAGE_DEFAULT_LIMIT,
                        None,
                        protocol::EVENT_PAGE_DEFAULT_LIMIT,
                    )
                    .await
                    .unwrap();
                if detail.session.status == status && detail.turns.len() >= minimum_turns {
                    break detail;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("the Session should reach the expected state and turn count")
    }

    async fn wait_for_no_armed_goals(store: &DemoStore) {
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if store.armed_session_goals().await.is_empty() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("Goal continuation authority should be disarmed");
    }

    async fn wait_for_agent_status(
        store: &DemoStore,
        authz: &AuthzContext,
        session_id: &str,
        turn_id: &str,
        expected: protocol::AgentTurnStatus,
    ) -> AgentTurnDetail {
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let detail = store
                    .agent_turn_detail_for_actor(authz, session_id, turn_id)
                    .await
                    .unwrap();
                if detail.status == expected {
                    break detail;
                }
                assert!(
                    !detail.status.is_terminal(),
                    "Agent reached terminal status {:?} while waiting for {:?}",
                    detail.status,
                    expected
                );
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("the durable Agent should reach the expected status")
    }

    fn insert_legacy_ready_session(path: &Path, session_id: &str, owner_user_id: &str) {
        let connection = Connection::open(path).unwrap();
        connection.busy_timeout(Duration::from_secs(1)).unwrap();
        connection
            .pragma_update(None, "foreign_keys", "ON")
            .unwrap();
        let timestamp = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        let title = "Legacy oversized Session";
        connection
            .execute(
                r#"INSERT INTO sessions(
                       id, title, status, created_at, updated_at, sequence,
                       projection_sequence, active_turn_id, owner_user_id, account_id
                   ) VALUES (?1, ?2, 'ready', ?3, ?3, 0, 0, NULL, ?4, 'acc_local')"#,
                params![session_id, title, timestamp, owner_user_id],
            )
            .unwrap();
        let event = SessionEvent {
            sequence: 1,
            id: format!("{session_id}:event:1"),
            at: timestamp.clone(),
            data: protocol::SessionEventData::SessionCreated {
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
                    event.id,
                    serde_json::to_string(&event).unwrap(),
                    timestamp,
                ],
            )
            .unwrap();
        assert_eq!(
            connection
                .execute(
                    r#"UPDATE sessions
                       SET sequence = 1, projection_sequence = 1
                       WHERE id = ?1"#,
                    [session_id],
                )
                .unwrap(),
            1
        );
    }

    async fn provision_test_owner(
        store: &DemoStore,
        user_id: &str,
        username: &str,
    ) -> TestIdentity {
        let bootstrap_hash = "1".repeat(64);
        let auth_session_id = AuthSessionId::generate().unwrap();
        let session_token = SessionToken::generate().unwrap();
        let csrf_token = CsrfToken::generate().unwrap();
        let expires_at = (chrono::Utc::now() + chrono::Duration::hours(1))
            .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        store
            .replace_bootstrap_token(&bootstrap_hash, &expires_at)
            .await
            .unwrap();
        store
            .bootstrap_owner(BootstrapOwnerCommit {
                bootstrap_token_hash: bootstrap_hash,
                user_id: user_id.into(),
                username: username.into(),
                password_hash: "$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$ZGlnaWVzdA".into(),
                auth_session_id: auth_session_id.clone(),
                session_token_hash: session_token.digest().to_persistence(),
                csrf_hash: csrf_token.digest().to_persistence(),
                session_expires_at: expires_at,
            })
            .await
            .unwrap();
        TestIdentity {
            user_id: user_id.into(),
            authz: AuthzContext {
                account_id: AccountId::local(),
                user_id: user_id.into(),
                membership_role: MembershipRole::Owner,
                membership_revision: tenancy::MembershipRevision::new(1).unwrap(),
                auth_session_id,
            },
            cookie_header: format!(
                "{SESSION_COOKIE}={}; {CSRF_COOKIE}={}",
                session_token.expose_secret(),
                csrf_token.expose_secret()
            ),
            csrf_token: csrf_token.expose_secret().into(),
        }
    }

    fn insert_test_member(path: &Path, user_id: &str, username: &str) -> TestIdentity {
        let auth_session_id = AuthSessionId::generate().unwrap();
        let session_token = SessionToken::generate().unwrap();
        let csrf_token = CsrfToken::generate().unwrap();
        let timestamp = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        let expires_at = (chrono::Utc::now() + chrono::Duration::hours(1))
            .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        let connection = Connection::open(path).unwrap();
        connection.busy_timeout(Duration::from_secs(1)).unwrap();
        connection
            .pragma_update(None, "foreign_keys", "ON")
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
                    timestamp,
                ],
            )
            .unwrap();
        connection
            .execute(
                r#"INSERT INTO user_preferences(
                       user_id, theme, preferred_model, revision, updated_at
                   ) VALUES (?1, 'system', NULL, 1, ?2)"#,
                params![user_id, timestamp],
            )
            .unwrap();
        connection
            .execute(
                r#"INSERT INTO account_memberships(
                       account_id, user_id, role, status, revision, created_at, updated_at
                   ) VALUES ('acc_local', ?1, 'member', 'active', 1, ?2, ?2)"#,
                params![user_id, timestamp],
            )
            .unwrap();
        connection
            .execute(
                r#"INSERT INTO auth_sessions(
                       id, token_hash, account_id, user_id, membership_revision,
                       csrf_hash, created_at, expires_at, last_seen_at
                   ) VALUES (?1, ?2, 'acc_local', ?3, 1, ?4, ?5, ?6, ?5)"#,
                params![
                    auth_session_id.as_str(),
                    session_token.digest().to_persistence(),
                    user_id,
                    csrf_token.digest().to_persistence(),
                    timestamp,
                    expires_at,
                ],
            )
            .unwrap();
        TestIdentity {
            user_id: user_id.into(),
            authz: AuthzContext {
                account_id: AccountId::local(),
                user_id: user_id.into(),
                membership_role: MembershipRole::Member,
                membership_revision: tenancy::MembershipRevision::new(1).unwrap(),
                auth_session_id,
            },
            cookie_header: format!(
                "{SESSION_COOKIE}={}; {CSRF_COOKIE}={}",
                session_token.expose_secret(),
                csrf_token.expose_secret()
            ),
            csrf_token: csrf_token.expose_secret().into(),
        }
    }

    fn transfer_test_session(path: &Path, session_id: &str, new_owner_user_id: &str) {
        let connection = Connection::open(path).unwrap();
        connection.busy_timeout(Duration::from_secs(1)).unwrap();
        connection
            .pragma_update(None, "foreign_keys", "ON")
            .unwrap();
        insert_test_foreign_account_owner(&connection, new_owner_user_id);
        connection
            .execute_batch(
                "DROP TRIGGER sessions_owner_is_write_once;
                 DROP TRIGGER sessions_account_is_immutable;",
            )
            .unwrap();
        assert_eq!(
            connection
                .execute(
                    r#"UPDATE sessions
                       SET owner_user_id = ?1, account_id = 'acc_other'
                       WHERE id = ?2"#,
                    params![new_owner_user_id, session_id],
                )
                .unwrap(),
            1
        );
    }

    fn transfer_test_run(path: &Path, run_id: &str, new_owner_user_id: &str) {
        let connection = Connection::open(path).unwrap();
        connection.busy_timeout(Duration::from_secs(1)).unwrap();
        connection
            .pragma_update(None, "foreign_keys", "ON")
            .unwrap();
        insert_test_foreign_account_owner(&connection, new_owner_user_id);
        connection
            .execute_batch(
                "DROP TRIGGER runs_owner_is_write_once;
                 DROP TRIGGER runs_account_is_immutable;",
            )
            .unwrap();
        assert_eq!(
            connection
                .execute(
                    r#"UPDATE runs
                       SET owner_user_id = ?1, account_id = 'acc_other'
                       WHERE id = ?2"#,
                    params![new_owner_user_id, run_id],
                )
                .unwrap(),
            1
        );
    }

    fn change_test_user_role(path: &Path, user_id: &str, role: &str) {
        let connection = Connection::open(path).unwrap();
        connection.busy_timeout(Duration::from_secs(1)).unwrap();
        assert_eq!(
            connection
                .execute(
                    "UPDATE users SET role = ?1, updated_at = ?2 WHERE id = ?3",
                    params![
                        role,
                        chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
                        user_id,
                    ],
                )
                .unwrap(),
            1
        );
    }

    fn bump_test_membership_revision(path: &Path, user_id: &str) {
        let connection = Connection::open(path).unwrap();
        connection.busy_timeout(Duration::from_secs(1)).unwrap();
        let timestamp = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        insert_test_backup_owner(&connection, &timestamp);
        assert_eq!(
            connection
                .execute(
                    r#"UPDATE account_memberships
                       SET role = 'member', revision = revision + 1, updated_at = ?1
                       WHERE account_id = 'acc_local' AND user_id = ?2"#,
                    params![timestamp, user_id],
                )
                .unwrap(),
            1
        );
    }

    fn invalidate_test_authority(path: &Path, user_id: &str, authority: &str) {
        let connection = Connection::open(path).unwrap();
        connection.busy_timeout(Duration::from_secs(1)).unwrap();
        let timestamp = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        let changed = match authority {
            "membership" => {
                insert_test_backup_owner(&connection, &timestamp);
                connection
                    .execute(
                        r#"UPDATE account_memberships
                           SET status = 'disabled', revision = revision + 1, updated_at = ?1
                           WHERE account_id = 'acc_local' AND user_id = ?2"#,
                        params![timestamp, user_id],
                    )
                    .unwrap()
            }
            "account" => connection
                .execute(
                    "UPDATE accounts SET status = 'suspended', updated_at = ?1 WHERE id = 'acc_local'",
                    [&timestamp],
                )
                .unwrap(),
            "user" => connection
                .execute(
                    "UPDATE users SET status = 'disabled', updated_at = ?1 WHERE id = ?2",
                    params![timestamp, user_id],
                )
                .unwrap(),
            _ => panic!("unknown authority fixture {authority}"),
        };
        assert_eq!(changed, 1);
    }

    fn insert_test_foreign_account_owner(connection: &Connection, user_id: &str) {
        let timestamp = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        connection
            .execute(
                r#"INSERT INTO accounts(id, name, status, created_at, updated_at)
                   VALUES ('acc_other', 'Other', 'active', ?1, ?1)"#,
                [&timestamp],
            )
            .unwrap();
        connection
            .execute(
                r#"INSERT INTO account_memberships(
                       account_id, user_id, role, status, revision, created_at, updated_at
                   ) VALUES ('acc_other', ?1, 'owner', 'active', 1, ?2, ?2)"#,
                params![user_id, timestamp],
            )
            .unwrap();
    }

    fn insert_test_backup_owner(connection: &Connection, timestamp: &str) {
        connection
            .execute(
                r#"INSERT INTO users(
                       id, username, role, status, password_hash, created_at, updated_at
                   ) VALUES (
                       'user-backup-owner', 'backup-owner', 'owner', 'active',
                       '$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$ZGlnaWVzdA', ?1, ?1
                   )"#,
                [timestamp],
            )
            .unwrap();
        connection
            .execute(
                r#"INSERT INTO account_memberships(
                       account_id, user_id, role, status, revision, created_at, updated_at
                   ) VALUES (
                       'acc_local', 'user-backup-owner', 'owner', 'active', 1, ?1, ?1
                   )"#,
                [timestamp],
            )
            .unwrap();
    }

    fn cleanup_test_database(path: &Path) {
        let mut lock_name = path.file_name().unwrap().to_os_string();
        lock_name.push(".zeus.lock");
        let lock_path = path.with_file_name(lock_name);
        let wal_path = PathBuf::from(format!("{}-wal", path.display()));
        let shm_path = PathBuf::from(format!("{}-shm", path.display()));
        for candidate in [path.to_path_buf(), wal_path, shm_path, lock_path] {
            match std::fs::remove_file(candidate) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => panic!("failed to clean up test database: {error}"),
            }
        }
    }

    async fn test_app() -> Router {
        app(DemoStore::seeded().await.unwrap()).await
    }

    async fn create_test_session(app: &Router, session_id: &str) -> CreateSessionResponse {
        let response = app
            .clone()
            .oneshot(
                Request::post("/api/v1/sessions")
                    .header(header::CONTENT_TYPE, "application/json")
                    .header("idempotency-key", format!("create-{session_id}"))
                    .body(Body::from(
                        serde_json::json!({
                            "id": session_id,
                            "title": "API test session",
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);
        response_json(response).await
    }

    async fn response_json<T: serde::de::DeserializeOwned>(response: Response) -> T {
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        serde_json::from_slice(&bytes).unwrap()
    }

    fn authentication_cookie_header(headers: &HeaderMap) -> String {
        headers
            .get_all(header::SET_COOKIE)
            .iter()
            .map(|value| value.to_str().unwrap().split(';').next().unwrap())
            .collect::<Vec<_>>()
            .join("; ")
    }
}
