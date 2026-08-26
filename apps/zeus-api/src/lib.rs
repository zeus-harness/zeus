//! HTTP composition for the durable Zeus Alpha slice.

use std::{
    collections::HashMap,
    convert::Infallible,
    net::{IpAddr, SocketAddr},
    sync::{Arc, Mutex as StdMutex},
    time::{Duration, Instant as StdInstant},
};

use axum::{
    Extension, Json, Router,
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
    routing::{get, post},
};
use llm::{
    LocalFallbackProvider, ProviderError, ReplyKind, ReplyMessage, ReplyProvider, ReplyRequest,
    ReplyRole,
};
use protocol::{
    AccountRole, AccountStatus, AccountUser, AssistantReplyKind, AssistantReplyProvenance,
    AuthStatusResponse, AuthenticationResponse, BootstrapRequest, CreateSessionRequest,
    CreateSessionResponse, HealthResponse, LoginRequest, LogoutResponse, ProblemDetails,
    ResumeSessionRequest, ResumeSessionResponse, ReviewRequest, ReviewResponse, RunDetail,
    SessionDetail, SessionEvent, SessionSummary, StartTurnRequest, ThemePreference,
    UpdatePreferencesRequest, UserPreferences,
};
use runtime::{
    AuthPrincipal, AuthSessionCommit, BootstrapOwnerCommit, DemoStore, PublishedEvent,
    ReplyClaimOutcome, ReplyFailureCommit, ReplyJob, ReplyJobSpec, ReplyOutcomeUnknownCommit,
    ReplySuccessCommit, StoreError, StoredPreferences, StoredUser, StoredUserRole,
    StoredUserStatus,
};
use serde::Deserialize;
use tenancy::{
    BootstrapTokenDigest, CsrfToken, CsrfTokenDigest, Password, PasswordAuthenticator,
    PasswordHashRecord, SessionToken, SessionTokenDigest, UserId, Username, hash_password,
};
use tokio::{
    sync::{Mutex, OwnedSemaphorePermit, Semaphore, broadcast},
    time::{Instant, MissedTickBehavior},
};
use zeroize::{Zeroize, Zeroizing};

const DURABLE_LEDGER_POLL_INTERVAL: Duration = Duration::from_secs(2);
const AUTH_JSON_BODY_MAX_BYTES: usize = 8 * 1024;
const COMMAND_JSON_BODY_MAX_BYTES: usize = 512 * 1024;
const PASSWORD_WORKER_LIMIT: usize = 2;
const AUTH_RATE_WINDOW: Duration = Duration::from_secs(60);
const AUTH_RATE_KEY_CAPACITY: usize = 4_096;
const AUTH_RATE_ENTRY_TTL: Duration = Duration::from_secs(15 * 60);
const AUTH_RATE_SWEEP_INTERVAL: Duration = Duration::from_secs(60);
const INVALID_LOGIN_ACCOUNT_KEY: &str = "<invalid-username>";
const SSE_GLOBAL_CONNECTION_LIMIT: usize = 64;
const SSE_ACTOR_CONNECTION_LIMIT: usize = 4;
const SSE_CAPACITY_RETRY_AFTER: Duration = Duration::from_secs(2);
const PERSISTED_REPLY_REQUEST_MAX_MESSAGES: usize = 64;

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
    cookie_secure: bool,
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
        Self {
            login: AttemptRateLimiter::new(login, Arc::clone(&clock)),
            bootstrap: AttemptRateLimiter::new(bootstrap, clock),
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
    actor_counts: StdMutex<HashMap<String, usize>>,
    per_actor_limit: usize,
}

struct SseLease {
    capacity: SseCapacity,
    actor_user_id: String,
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

    fn try_acquire(&self, actor_user_id: &str) -> Result<SseLease, RateLimitError> {
        let global_permit = Arc::clone(&self.inner.global)
            .try_acquire_owned()
            .map_err(|_| RateLimitError::Limited(SSE_CAPACITY_RETRY_AFTER))?;
        let mut actor_counts = self
            .inner
            .actor_counts
            .lock()
            .map_err(|_| RateLimitError::Unavailable)?;
        let actor_count = actor_counts.entry(actor_user_id.to_owned()).or_default();
        if *actor_count >= self.inner.per_actor_limit {
            return Err(RateLimitError::Limited(SSE_CAPACITY_RETRY_AFTER));
        }
        *actor_count += 1;
        drop(actor_counts);
        Ok(SseLease {
            capacity: self.clone(),
            actor_user_id: actor_user_id.to_owned(),
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
        if let Some(actor_count) = actor_counts.get_mut(&self.actor_user_id) {
            *actor_count = actor_count.saturating_sub(1);
            if *actor_count == 0 {
                actor_counts.remove(&self.actor_user_id);
            }
        }
    }
}

struct ReplyExecutor {
    provider: Arc<dyn ReplyProvider>,
    drain: Mutex<()>,
}

#[derive(Clone)]
struct CurrentAuth {
    principal: AuthPrincipal,
    session_token_hash: String,
}

#[cfg(test)]
#[derive(Clone)]
struct TestRequestAuth {
    user_id: String,
    cookie_header: HeaderValue,
    csrf_token: HeaderValue,
}

#[derive(Debug, Default, Deserialize)]
struct EventsQuery {
    after: Option<u64>,
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
    let auth = auth_config_with_clock(cookie_secure, Arc::new(SystemRateLimitClock))?;
    let reply = Arc::new(ReplyExecutor {
        provider,
        drain: Mutex::new(()),
    });
    let state = ApiState {
        store,
        durable_ledger_poll_interval: DURABLE_LEDGER_POLL_INTERVAL,
        broadcast_hints_enabled: true,
        auth: Some(auth),
        reply: Some(reply),
        sse_capacity: SseCapacity::production(),
    };
    Ok(build_authenticated_app(state))
}

fn auth_config_with_clock(
    cookie_secure: bool,
    clock: Arc<dyn RateLimitClock>,
) -> Result<Arc<AuthConfig>, tenancy::CredentialError> {
    Ok(Arc::new(AuthConfig {
        authenticator: Arc::new(PasswordAuthenticator::new()?),
        password_workers: Arc::new(Semaphore::new(PASSWORD_WORKER_LIMIT)),
        rate_limits: AuthRateLimits::new(clock),
        cookie_secure,
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
        .route("/api/v1/sessions/{id}/resume", post(resume_session))
        .route("/api/v1/sessions/{id}/turns", post(start_turn))
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
        .route_layer(middleware::from_fn_with_state(state.clone(), require_auth))
        .layer(DefaultBodyLimit::max(COMMAND_JSON_BODY_MAX_BYTES));

    let public = Router::new()
        .route("/health/live", get(liveness))
        .route("/health/ready", get(readiness))
        .route("/api/v1/auth/status", get(auth_status))
        .route("/api/v1/auth/bootstrap", post(bootstrap))
        .route("/api/v1/auth/login", post(login))
        .layer(DefaultBodyLimit::max(AUTH_JSON_BODY_MAX_BYTES));

    let router = public
        .merge(protected)
        .fallback(not_found)
        .with_state(state.clone());
    kick_reply_worker(&state);
    router
}

#[cfg(test)]
async fn app(store: DemoStore) -> Router {
    app_with_event_feed_options(store, DURABLE_LEDGER_POLL_INTERVAL, true).await
}

#[cfg(test)]
async fn app_with_event_feed_options(
    store: DemoStore,
    durable_ledger_poll_interval: Duration,
    broadcast_hints_enabled: bool,
) -> Router {
    assert!(
        !durable_ledger_poll_interval.is_zero(),
        "the durable ledger poll interval must be positive"
    );
    let request_auth = configure_test_actor(&store).await;
    let auth = auth_config_with_clock(false, Arc::new(SystemRateLimitClock)).unwrap();
    let state = ApiState {
        store,
        durable_ledger_poll_interval,
        broadcast_hints_enabled,
        auth: Some(auth),
        reply: None,
        sse_capacity: SseCapacity::production(),
    };
    build_test_app(state, request_auth)
}

#[cfg(test)]
fn build_test_app(state: ApiState, request_auth: TestRequestAuth) -> Router {
    let protected = Router::new()
        .route("/api/v1/overview", get(overview))
        .route("/api/v1/sessions", get(list_sessions).post(create_session))
        .route("/api/v1/sessions/{id}", get(session_detail))
        .route("/api/v1/sessions/{id}/resume", post(resume_session))
        .route("/api/v1/sessions/{id}/turns", post(test_start_turn))
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
            session_token_hash: session_token.digest().to_persistence(),
            csrf_hash: csrf_token.digest().to_persistence(),
            session_expires_at: expires_at,
        })
        .await
        .expect("the test owner should claim the seeded resources");
    TestRequestAuth {
        user_id: "user-test-owner".into(),
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
    state.store.readiness().await?;
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
    let (user, preferences) = if let Some(principal) = principal {
        let preferences = state.store.preferences(&principal.user.id).await?;
        (
            Some(account_user(&principal.user)),
            Some(user_preferences(&preferences)?),
        )
    } else {
        (None, None)
    };
    let mut response = Json(AuthStatusResponse {
        configured,
        authenticated: user.is_some(),
        user,
        preferences,
    })
    .into_response();
    no_store(response.headers_mut());
    Ok(response)
}

async fn bootstrap(
    State(state): State<ApiState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    payload: Result<Json<BootstrapRequest>, JsonRejection>,
) -> Result<Response, ApiError> {
    enforce_same_origin(&headers)?;
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
        peer.ip(),
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
    let (session_token, csrf_token, expires_at) = fresh_auth_tokens()?;
    let (user, preferences) = state
        .store
        .bootstrap_owner(BootstrapOwnerCommit {
            bootstrap_token_hash: bootstrap_hash,
            user_id: user_id.as_str().to_owned(),
            username: username.as_str().to_owned(),
            password_hash: password_hash.as_phc().to_owned(),
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
        user,
        preferences,
    )
}

async fn login(
    State(state): State<ApiState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    payload: Result<Json<LoginRequest>, JsonRejection>,
) -> Result<Response, ApiError> {
    enforce_same_origin(&headers)?;
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
    let account_key = normalized_username
        .as_ref()
        .map(Username::as_str)
        .unwrap_or(INVALID_LOGIN_ACCOUNT_KEY);
    let auth = auth_config(&state)?;
    charge_auth_rate_limit(
        &auth.rate_limits.login,
        peer.ip(),
        Some(account_key),
        "login_rate_limited",
        "Sign-in temporarily limited",
    )?;
    let credential = if let Some(username) = &normalized_username {
        state
            .store
            .credential_for_username(username.as_str())
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
    let credential = credential.filter(|credential| {
        verified
            && credential.user.status == StoredUserStatus::Active
            && credential.user.role == StoredUserRole::Owner
    });
    let Some(credential) = credential else {
        return Err(ApiError::invalid_login());
    };

    let (session_token, csrf_token, expires_at) = fresh_auth_tokens()?;
    state
        .store
        .create_auth_session(AuthSessionCommit {
            user_id: credential.user.id.clone(),
            session_token_hash: session_token.digest().to_persistence(),
            csrf_hash: csrf_token.digest().to_persistence(),
            expires_at: expires_at.clone(),
        })
        .await?;
    let preferences = state.store.preferences(&credential.user.id).await?;
    authentication_response(
        &state,
        &session_token,
        &csrf_token,
        &expires_at,
        credential.user,
        preferences,
    )
}

async fn logout(
    State(state): State<ApiState>,
    Extension(current): Extension<CurrentAuth>,
) -> Result<Response, ApiError> {
    state
        .store
        .revoke_auth_session(&current.session_token_hash)
        .await?;
    let mut response = Json(LogoutResponse {
        status: "signed_out".into(),
    })
    .into_response();
    clear_auth_cookies(response.headers_mut(), auth_config(&state)?.cookie_secure)?;
    no_store(response.headers_mut());
    Ok(response)
}

async fn get_preferences(
    State(state): State<ApiState>,
    Extension(current): Extension<CurrentAuth>,
) -> Result<Json<UserPreferences>, ApiError> {
    let preferences = state.store.preferences(&current.principal.user.id).await?;
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
    let preferred_model = request
        .preferred_model
        .as_deref()
        .map(str::trim)
        .filter(|model| !model.is_empty());
    if preferred_model.is_some()
        && preferred_model != reply_executor(&state)?.provider.metadata().model.as_deref()
    {
        return Err(ApiError::bad_request(
            "unsupported_model",
            "The preferred model must match the server-configured provider model",
        ));
    }
    let preferences = state
        .store
        .update_preferences(
            &current.principal.user.id,
            request.expected_revision,
            theme,
            preferred_model,
        )
        .await?;
    Ok(Json(user_preferences(&preferences)?))
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
        if principal.user.role != StoredUserRole::Owner {
            return Err(ApiError::unauthorized());
        }

        if is_unsafe_method(request.method()) {
            enforce_same_origin(headers)?;
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

fn acquire_sse_lease(capacity: &SseCapacity, actor_user_id: &str) -> Result<SseLease, ApiError> {
    match capacity.try_acquire(actor_user_id) {
        Ok(lease) => Ok(lease),
        Err(RateLimitError::Limited(retry_after)) => {
            Err(ApiError::sse_capacity_exceeded(retry_after))
        }
        Err(RateLimitError::Unavailable) => Err(ApiError::unavailable_message(
            "SSE connection capacity is temporarily unavailable",
        )),
    }
}

fn fresh_auth_tokens() -> Result<(SessionToken, CsrfToken, String), ApiError> {
    let session = SessionToken::generate().map_err(|error| ApiError::auth_unavailable(&error))?;
    let csrf = CsrfToken::generate().map_err(|error| ApiError::auth_unavailable(&error))?;
    let expires_at = (chrono::Utc::now() + chrono::Duration::seconds(AUTH_SESSION_SECONDS))
        .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    Ok((session, csrf, expires_at))
}

fn authentication_response(
    state: &ApiState,
    session_token: &SessionToken,
    csrf_token: &CsrfToken,
    expires_at: &str,
    user: StoredUser,
    preferences: StoredPreferences,
) -> Result<Response, ApiError> {
    let mut response = Json(AuthenticationResponse {
        user: account_user(&user),
        preferences: user_preferences(&preferences)?,
        csrf_token: csrf_token.expose_secret().to_owned(),
        expires_at: expires_at.to_owned(),
    })
    .into_response();
    set_auth_cookies(
        response.headers_mut(),
        session_token.expose_secret(),
        csrf_token.expose_secret(),
        auth_config(state)?.cookie_secure,
    )?;
    no_store(response.headers_mut());
    Ok(response)
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
    Ok(state
        .store
        .authenticate(&digest.to_persistence())
        .await?
        .filter(|principal| principal.user.role == StoredUserRole::Owner))
}

fn account_user(user: &StoredUser) -> AccountUser {
    AccountUser {
        id: user.id.clone(),
        username: user.username.clone(),
        role: match user.role {
            StoredUserRole::Owner => AccountRole::Owner,
            StoredUserRole::Member => AccountRole::Member,
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

fn enforce_same_origin(headers: &HeaderMap) -> Result<(), ApiError> {
    let origin = headers
        .get(header::ORIGIN)
        .and_then(|value| value.to_str().ok())
        .ok_or_else(ApiError::invalid_origin)?;
    let host = headers
        .get(header::HOST)
        .and_then(|value| value.to_str().ok())
        .ok_or_else(ApiError::invalid_origin)?;
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

fn reply_executor(state: &ApiState) -> Result<&ReplyExecutor, ApiError> {
    state
        .reply
        .as_deref()
        .ok_or_else(|| ApiError::auth_unavailable("reply execution is not configured"))
}

fn kick_reply_worker(state: &ApiState) {
    if state.reply.is_none() {
        return;
    }
    let Ok(runtime) = tokio::runtime::Handle::try_current() else {
        return;
    };
    let state = state.clone();
    runtime.spawn(async move {
        if let Err(error) = drain_reply_jobs(&state).await {
            eprintln!("zeus reply worker stopped: {error}");
        }
    });
}

async fn drain_reply_jobs(state: &ApiState) -> Result<(), StoreError> {
    let reply = state
        .reply
        .as_ref()
        .expect("reply worker is only started when a provider exists");
    let _drain = reply.drain.lock().await;
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
    let metadata = reply.provider.metadata();
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
    let response = match reply.provider.reply(request).await {
        Ok(response) => response,
        Err(error) => {
            if matches!(&error, ProviderError::Timeout | ProviderError::Transport) {
                return mark_reply_outcome_unknown(
                    state,
                    &job,
                    provider_error_code(&error),
                    &error.to_string(),
                )
                .await;
            }
            return fail_reply_job(state, &job, provider_error_code(&error), &error.to_string())
                .await;
        }
    };
    if &response.provider != metadata {
        return fail_reply_job(
            state,
            &job,
            "provider_metadata_mismatch",
            "The reply provider returned inconsistent provenance",
        )
        .await;
    }

    let expected_sequence = state
        .store
        .get_session(&job.session_id)
        .await?
        .session
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
            assistant_message: response.content,
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
    Ok(())
}

fn persisted_reply_request_fits_envelope(request: &ReplyRequest) -> bool {
    if request.messages.is_empty() || request.messages.len() > PERSISTED_REPLY_REQUEST_MAX_MESSAGES
    {
        return false;
    }

    let mut total_bytes = 0usize;
    for message in &request.messages {
        if protocol::validate_user_message(&message.content).is_err() {
            return false;
        }
        let Some(updated_total) = total_bytes.checked_add(message.content.len()) else {
            return false;
        };
        if updated_total > protocol::USER_MESSAGE_MAX_BYTES {
            return false;
        }
        total_bytes = updated_total;
    }
    true
}

async fn fail_reply_job(
    state: &ApiState,
    job: &ReplyJob,
    code: &str,
    message: &str,
) -> Result<(), StoreError> {
    let expected_sequence = state
        .store
        .get_session(&job.session_id)
        .await?
        .session
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
        .get_session(&job.session_id)
        .await?
        .session
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
        ProviderError::Timeout => "provider_timeout",
        ProviderError::Transport => "provider_transport_failed",
        ProviderError::HttpStatus { .. } => "provider_http_error",
        ProviderError::ResponseTooLarge { .. } => "provider_response_too_large",
        ProviderError::InvalidResponse => "provider_response_invalid",
    }
}

async fn overview(
    State(state): State<ApiState>,
    Extension(current): Extension<CurrentAuth>,
) -> Result<Json<protocol::OverviewResponse>, ApiError> {
    Ok(Json(
        state
            .store
            .overview_for_actor(&current.principal.user.id)
            .await?,
    ))
}

async fn list_sessions(
    State(state): State<ApiState>,
    Extension(current): Extension<CurrentAuth>,
) -> Result<Json<Vec<SessionSummary>>, ApiError> {
    Ok(Json(
        state
            .store
            .list_sessions_for_actor(&current.principal.user.id)
            .await?,
    ))
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
        .create_session_for_actor(&current.principal.user.id, request, &idempotency_key)
        .await?;
    Ok((StatusCode::CREATED, Json(response)))
}

async fn session_detail(
    State(state): State<ApiState>,
    Extension(current): Extension<CurrentAuth>,
    Path(id): Path<String>,
) -> Result<Json<SessionDetail>, ApiError> {
    Ok(Json(
        state
            .store
            .get_session_for_actor(&current.principal.user.id, &id)
            .await?,
    ))
}

async fn resume_session(
    State(state): State<ApiState>,
    Extension(current): Extension<CurrentAuth>,
    Path(id): Path<String>,
    headers: HeaderMap,
    payload: Result<Json<ResumeSessionRequest>, JsonRejection>,
) -> Result<Json<ResumeSessionResponse>, ApiError> {
    let Json(request) = payload.map_err(ApiError::invalid_json)?;
    let idempotency_key = required_idempotency_key(&headers)?;
    Ok(Json(
        state
            .store
            .resume_session_for_actor(&current.principal.user.id, &id, request, &idempotency_key)
            .await?,
    ))
}

async fn start_turn(
    State(state): State<ApiState>,
    Extension(current): Extension<CurrentAuth>,
    Path(id): Path<String>,
    headers: HeaderMap,
    payload: Result<Json<StartTurnRequest>, JsonRejection>,
) -> Result<Response, ApiError> {
    let Json(request) = payload.map_err(ApiError::invalid_json)?;
    let idempotency_key = required_idempotency_key(&headers)?;
    validate_start_turn_envelope(&request)?;
    let reply = reply_executor(&state)?;
    let metadata = reply.provider.metadata();
    let reply_request = ReplyRequest::new([ReplyMessage::new(
        ReplyRole::User,
        request.user_message.clone(),
    )]);
    let job = ReplyJobSpec {
        id: format!("reply:{id}:{}", request.turn_id),
        actor_user_id: current.principal.user.id.clone(),
        provider_name: metadata.provider_id.clone(),
        model_name: metadata.model.clone(),
        request_json: serde_json::to_value(reply_request)
            .map_err(|error| ApiError::auth_unavailable(&error))?,
    };
    let response = state
        .store
        .start_turn_and_enqueue_reply_for_actor(
            &current.principal.user.id,
            &id,
            request,
            &idempotency_key,
            job,
        )
        .await?;
    kick_reply_worker(&state);
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
    let Json(request) = payload.map_err(ApiError::invalid_json)?;
    let idempotency_key = required_idempotency_key(&headers)?;
    Ok(Json(
        state
            .store
            .start_turn_for_actor(&current.principal.user.id, &id, request, &idempotency_key)
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
            .flush_turn_for_actor(&current.principal.user.id, &id, request, &idempotency_key)
            .await?,
    ))
}

async fn run_detail(
    State(state): State<ApiState>,
    Extension(current): Extension<CurrentAuth>,
    Path(id): Path<String>,
) -> Result<Json<RunDetail>, ApiError> {
    Ok(Json(
        state
            .store
            .run_detail_for_actor(&current.principal.user.id, &id)
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
                &current.principal.user.id,
                &id,
                &approval_id,
                request,
                &header_key,
            )
            .await?,
    ))
}

fn required_idempotency_key(headers: &HeaderMap) -> Result<String, ApiError> {
    let mut values = headers.get_all("idempotency-key").iter();
    let value = values.next().ok_or_else(|| {
        ApiError::bad_request(
            "missing_idempotency_key",
            "Idempotency-Key header is required for POST requests",
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

async fn session_events(
    State(state): State<ApiState>,
    Extension(current): Extension<CurrentAuth>,
    Path(id): Path<String>,
    headers: HeaderMap,
    query: Result<Query<EventsQuery>, QueryRejection>,
) -> Result<Response, ApiError> {
    let Query(query) = query.map_err(ApiError::invalid_query)?;
    let after = event_cursor(&headers, query)?;
    if !sse_auth_is_current(&state.store, &current).await {
        return Err(ApiError::unauthorized());
    }
    let actor_user_id = current.principal.user.id.clone();
    let sse_lease = acquire_sse_lease(&state.sse_capacity, &actor_user_id)?;
    let mut feed = state
        .store
        .session_event_feed_for_actor(&actor_user_id, &id, after)
        .await?;
    let store = state.store.clone();
    let durable_ledger_poll_interval = state.durable_ledger_poll_interval;
    let broadcast_hints_enabled = state.broadcast_hints_enabled;
    let session_id = id;

    let stream = async_stream::stream! {
        let _sse_lease = sse_lease;
        let mut cursor = after;
        for event in feed.replay {
            cursor = cursor.max(event.sequence);
            yield Ok::<Event, Infallible>(session_sse_event(&event));
        }

        yield Ok(Event::default().comment("stream-open"));

        let mut durable_poll = tokio::time::interval_at(
            Instant::now() + durable_ledger_poll_interval,
            durable_ledger_poll_interval,
        );
        durable_poll.set_missed_tick_behavior(MissedTickBehavior::Delay);

        loop {
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
                                .session_events_after_for_actor(
                                    &actor_user_id,
                                    &session_id,
                                    cursor,
                                )
                                .await
                            {
                                Ok(events) => {
                                    for event in events {
                                        if event.sequence > cursor {
                                            cursor = event.sequence;
                                            yield Ok(session_sse_event(&event));
                                        }
                                    }
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
                            .session_events_after_for_actor(&actor_user_id, &session_id, cursor)
                            .await
                        {
                            Ok(events) => {
                                for event in events {
                                    if event.sequence > cursor {
                                        cursor = event.sequence;
                                        yield Ok(session_sse_event(&event));
                                    }
                                }
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
                        .session_events_after_for_actor(&actor_user_id, &session_id, cursor)
                        .await
                    {
                        Ok(events) => {
                            for event in events {
                                if event.sequence > cursor {
                                    cursor = event.sequence;
                                    yield Ok(session_sse_event(&event));
                                }
                            }
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
    let Query(query) = query.map_err(ApiError::invalid_query)?;
    let after = event_cursor(&headers, query)?;
    if !sse_auth_is_current(&state.store, &current).await {
        return Err(ApiError::unauthorized());
    }
    let actor_user_id = current.principal.user.id.clone();
    let sse_lease = acquire_sse_lease(&state.sse_capacity, &actor_user_id)?;
    let mut feed = state
        .store
        .event_feed_for_actor(&actor_user_id, &id, after)
        .await?;
    let store = state.store.clone();
    let durable_ledger_poll_interval = state.durable_ledger_poll_interval;
    let broadcast_hints_enabled = state.broadcast_hints_enabled;
    let run_id = id;

    let stream = async_stream::stream! {
        let _sse_lease = sse_lease;
        let mut cursor = after;
        for event in feed.replay {
            cursor = cursor.max(event.sequence);
            yield Ok::<Event, Infallible>(sse_event(&event));
        }

        // Flush a harmless SSE comment even when the client is already at the
        // ledger head. Some development proxies buffer response headers until
        // the first body chunk, which otherwise leaves the UI looking as if it
        // is reconnecting until the first keep-alive interval.
        yield Ok(Event::default().comment("stream-open"));

        // Broadcast is a same-process latency hint only. Poll the durable
        // ledger at a bounded interval so commits without a local hint are
        // still observed. Delay missed ticks to avoid catch-up bursts.
        let mut durable_poll = tokio::time::interval_at(
            Instant::now() + durable_ledger_poll_interval,
            durable_ledger_poll_interval,
        );
        durable_poll.set_missed_tick_behavior(MissedTickBehavior::Delay);

        loop {
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
                            &actor_user_id,
                            &run_id,
                            cursor,
                            &published,
                        )
                        .await
                        {
                            Ok(events) => {
                                for event in events {
                                    if event.sequence > cursor {
                                        cursor = event.sequence;
                                        yield Ok(sse_event(&event));
                                    }
                                }
                            }
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
                            .events_after_for_actor(&actor_user_id, &run_id, cursor)
                            .await
                        {
                            Ok(events) => {
                                for event in events {
                                    if event.sequence > cursor {
                                        cursor = event.sequence;
                                        yield Ok(sse_event(&event));
                                    }
                                }
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
                        .events_after_for_actor(&actor_user_id, &run_id, cursor)
                        .await
                    {
                        Ok(events) => {
                            for event in events {
                                if event.sequence > cursor {
                                    cursor = event.sequence;
                                    yield Ok(sse_event(&event));
                                }
                            }
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
            if principal.user.id == current.principal.user.id
                && principal.user.role == StoredUserRole::Owner
                && principal.user.status == StoredUserStatus::Active
    )
}

async fn run_events_for_hint(
    store: &DemoStore,
    actor_user_id: &str,
    run_id: &str,
    cursor: u64,
    published: &PublishedEvent,
) -> Result<Vec<protocol::RunEvent>, StoreError> {
    if published.run_id != run_id || published.event.sequence <= cursor {
        return Ok(Vec::new());
    }
    store
        .events_after_for_actor(actor_user_id, run_id, cursor)
        .await
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
    let header_cursor = headers
        .get("last-event-id")
        .map(|value| {
            value
                .to_str()
                .map_err(|_| ())
                .and_then(|value| value.parse::<u64>().map_err(|_| ()))
                .map_err(|_| {
                    ApiError::bad_request(
                        "invalid_event_cursor",
                        "Last-Event-ID must be an unsigned integer sequence",
                    )
                })
        })
        .transpose()?;
    // EventSource keeps the original query string when reconnecting but sends
    // its newer cursor in Last-Event-ID. Prefer that header so reconnects do
    // not repeatedly replay from the page's initial sequence.
    Ok(header_cursor.or(query.after).unwrap_or(0))
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

    fn auth_unavailable(error: &(impl std::fmt::Display + ?Sized)) -> Self {
        eprintln!("zeus authentication subsystem failed: {error}");
        Self::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "authentication_unavailable",
            "Authentication is unavailable",
            "The authentication subsystem could not process the request safely",
        )
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

    fn unavailable_message(detail: &'static str) -> Self {
        eprintln!("zeus API capacity state is unavailable");
        Self::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "service_unavailable",
            "Service is unavailable",
            detail,
        )
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
    }

    fn unavailable(error: &StoreError) -> Self {
        eprintln!("zeus request failed because the runtime is unavailable: {error:?}");
        Self::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "runtime_unavailable",
            "Runtime is unavailable",
            "The runtime is temporarily unavailable",
        )
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
            | StoreError::ExecutionInvariant(_)
            | StoreError::Kernel(_)
            | StoreError::SequenceOverflow => Self::internal_runtime_error(&error),
            StoreError::ConcurrentModification => Self::new(
                StatusCode::CONFLICT,
                "concurrent_modification",
                "Concurrent modification",
                "The resource changed while the command was being committed; retry the request",
            ),
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
    use llm::{ProviderMetadata, ReplyFuture};
    use protocol::{
        CreateSessionResponse, DEMO_RUN_ID, FlushSessionResponse, OverviewResponse, ReviewDecision,
        ReviewRequest, ReviewResponse, SessionDetail, SessionStatus, SessionSummary,
        StartTurnResponse,
    };
    use rusqlite::{Connection, params};
    use tenancy::BootstrapToken;
    use tower::ServiceExt;

    use super::*;

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
        let capacity = SseCapacity::new(2, 2);
        let alice_one = capacity.try_acquire("alice").unwrap();
        let alice_two = capacity.try_acquire("alice").unwrap();
        assert!(matches!(
            capacity.try_acquire("bob"),
            Err(RateLimitError::Limited(retry_after)) if retry_after == SSE_CAPACITY_RETRY_AFTER
        ));
        drop(alice_one);
        let bob = capacity.try_acquire("bob").unwrap();
        assert!(matches!(
            capacity.try_acquire("alice"),
            Err(RateLimitError::Limited(retry_after)) if retry_after == SSE_CAPACITY_RETRY_AFTER
        ));
        drop(alice_two);
        drop(bob);
        assert!(capacity.try_acquire("alice").is_ok());
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
            cookie_secure: false,
        });
        let state = ApiState {
            store,
            durable_ledger_poll_interval: DURABLE_LEDGER_POLL_INTERVAL,
            broadcast_hints_enabled: true,
            auth: Some(auth),
            reply: Some(Arc::new(ReplyExecutor {
                provider: Arc::new(LocalFallbackProvider::new()),
                drain: Mutex::new(()),
            })),
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
    async fn unknown_wrong_disabled_and_member_login_failures_are_indistinguishable() {
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

        update_test_user_access(&fixture.path, "member", "active");
        failures.push(
            fixture
                .app
                .clone()
                .oneshot(login_request("owner", TEST_OWNER_PASSWORD))
                .await
                .unwrap(),
        );
        update_test_user_access(&fixture.path, "owner", "disabled");
        failures.push(
            fixture
                .app
                .clone()
                .oneshot(login_request("owner", TEST_OWNER_PASSWORD))
                .await
                .unwrap(),
        );

        let mut expected_problem = None;
        for response in failures {
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
            assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
            let problem: ProblemDetails = response_json(response).await;
            assert_eq!(problem.code, "invalid_credentials");
            if let Some(expected) = &expected_problem {
                assert_eq!(&problem, expected);
            } else {
                expected_problem = Some(problem);
            }
        }

        update_test_user_access(&fixture.path, "owner", "active");
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
        Timeout,
        Transport,
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
                    IndeterminateFailure::Timeout => ProviderError::Timeout,
                    IndeterminateFailure::Transport => ProviderError::Transport,
                })
            })
        }
    }

    struct CountingProvider {
        metadata: ProviderMetadata,
        calls: Arc<AtomicUsize>,
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
                    .get_session_for_actor(&owner.user_id, &session_id)
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
                &identity.user_id,
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
                &identity.user_id,
                session_id,
                StartTurnRequest {
                    turn_id: turn_id.into(),
                    user_message: "valid legacy placeholder".into(),
                    expected_sequence: 1,
                },
                "start-legacy-oversized-reply",
                ReplyJobSpec {
                    id: job_id.into(),
                    actor_user_id: identity.user_id.clone(),
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
            reply: Some(Arc::new(ReplyExecutor {
                provider,
                drain: Mutex::new(()),
            })),
            sse_capacity: SseCapacity::production(),
        };

        process_reply_job(&state, *job).await.unwrap();

        assert_eq!(provider_calls.load(Ordering::Relaxed), 0);
        let stored = store.reply_job(job_id).await.unwrap().unwrap();
        assert_eq!(stored.status, runtime::ReplyJobStatus::Failed);
        assert_eq!(
            stored.error_json.unwrap()["code"],
            "persisted_request_exceeds_resource_envelope"
        );
        let detail = store.get_session(session_id).await.unwrap();
        assert_eq!(detail.session.status, SessionStatus::NeedsAttention);
        assert!(matches!(
            &detail.events.last().unwrap().data,
            protocol::SessionEventData::TurnInterrupted { reason, .. }
                if reason == "assistant reply provider failed"
        ));
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
        ] {
            let store = DemoStore::seeded().await.unwrap();
            let bootstrap_hash = "d".repeat(64);
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
                    session_token_hash: "e".repeat(64),
                    csrf_hash: "f".repeat(64),
                    session_expires_at: expires_at,
                })
                .await
                .unwrap();
            let session_id = format!("session-{suffix}");
            let turn_id = format!("turn-{suffix}");
            let job_id = format!("reply-{suffix}");
            store
                .create_session_for_actor(
                    "user-owner",
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
                    "user-owner",
                    &session_id,
                    StartTurnRequest {
                        turn_id: turn_id.clone(),
                        user_message: "settle this reply safely".into(),
                        expected_sequence: 1,
                    },
                    &format!("start-{suffix}"),
                    ReplyJobSpec {
                        id: job_id.clone(),
                        actor_user_id: "user-owner".into(),
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
                reply: Some(Arc::new(ReplyExecutor {
                    provider,
                    drain: Mutex::new(()),
                })),
                sse_capacity: SseCapacity::production(),
            };

            process_reply_job(&state, *job).await.unwrap();

            let stored = store.reply_job(&job_id).await.unwrap().unwrap();
            assert_eq!(stored.status, runtime::ReplyJobStatus::OutcomeUnknown);
            assert_eq!(stored.error_json.unwrap()["code"], expected_code);
            let detail = store.get_session(&session_id).await.unwrap();
            assert_eq!(detail.session.status, SessionStatus::NeedsAttention);
            assert!(matches!(
                &detail.events.last().unwrap().data,
                protocol::SessionEventData::TurnInterrupted { reason, .. }
                    if reason == "assistant reply provider outcome is unknown"
            ));
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
    }

    #[tokio::test]
    async fn cross_actor_rest_and_sse_are_not_found_and_live_sse_closes_on_owner_change() {
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

        // Production ownership is immutable. This test-only database mutation
        // simulates a future administrative transfer and proves the stream
        // does not keep relying on the authorization snapshot from open time.
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

        let resume = app
            .clone()
            .oneshot(
                Request::post(format!("/api/v1/sessions/{session_id}/resume"))
                    .header(header::HOST, "zeus.test")
                    .header(header::ORIGIN, "http://zeus.test")
                    .header(header::COOKIE, &alice.cookie_header)
                    .header(CSRF_HEADER, &alice.csrf_token)
                    .header(header::CONTENT_TYPE, "application/json")
                    .header("idempotency-key", "resume-cross-actor")
                    .body(Body::from(r#"{"expected_sequence":1}"#))
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
                Request::get(format!("/api/v1/sessions/{session_id}/events?after=0"))
                    .header(header::COOKIE, &alice.cookie_header)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(cross_actor_sse.status(), StatusCode::NOT_FOUND);

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

        let member_cookie = app
            .clone()
            .oneshot(
                Request::get("/api/v1/sessions/session-ZR-1842")
                    .header(header::COOKIE, &bob.cookie_header)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(member_cookie.status(), StatusCode::UNAUTHORIZED);

        drop(app);
        drop(store);
        cleanup_test_database(&path);
    }

    #[tokio::test]
    async fn cross_actor_run_rest_review_and_sse_are_not_found_and_live_sse_closes() {
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
                .header("idempotency-key", "review-cross-actor")
                .body(Body::from(r#"{"decision":"reject"}"#))
                .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(review.status(), StatusCode::NOT_FOUND);

        let cross_actor_sse = app
            .clone()
            .oneshot(
                Request::get(format!("/api/v1/runs/{DEMO_RUN_ID}/events?after=0"))
                    .header(header::COOKIE, &alice.cookie_header)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(cross_actor_sse.status(), StatusCode::NOT_FOUND);

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
    async fn sse_closes_when_the_authenticated_actor_role_changes() {
        let (app, store, alice, path) = authenticated_file_app("role-change").await;
        let sse = app
            .clone()
            .oneshot(
                Request::get("/api/v1/sessions/session-ZR-1842/events?after=999")
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
        let ended = tokio::time::timeout(Duration::from_secs(3), body.frame())
            .await
            .expect("role-changed SSE should close by the next durable poll");
        assert!(ended.is_none(), "role-changed SSE emitted another frame");

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

        drop(app);
        drop(store);
        cleanup_test_database(&path);
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

    #[tokio::test]
    async fn sse_polls_the_ledger_without_local_broadcast_hints() {
        let store = DemoStore::seeded().await.unwrap();
        let response = app_with_event_feed_options(store.clone(), Duration::from_millis(10), false)
            .await
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
                "user-test-owner",
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
                &current.user_id,
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

        let detail = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let detail = store.run_detail(DEMO_RUN_ID).await.unwrap();
                if detail.run.sequence >= 11 {
                    break detail;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("the guarded demo dispatcher should settle durably");
        let hinted = detail.events.last().cloned().unwrap();
        assert_eq!(hinted.sequence, 11);

        let replay = run_events_for_hint(
            &store,
            &current.user_id,
            DEMO_RUN_ID,
            8,
            &PublishedEvent {
                run_id: DEMO_RUN_ID.into(),
                event: hinted,
            },
        )
        .await
        .unwrap();
        assert_eq!(
            replay
                .iter()
                .map(|event| event.sequence)
                .collect::<Vec<_>>(),
            vec![9, 10, 11]
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
            cookie_secure: false,
        });
        let state = ApiState {
            store: store.clone(),
            durable_ledger_poll_interval: DURABLE_LEDGER_POLL_INTERVAL,
            broadcast_hints_enabled: true,
            auth: Some(Arc::clone(&auth)),
            reply: Some(Arc::new(ReplyExecutor {
                provider: Arc::new(LocalFallbackProvider::new()),
                drain: Mutex::new(()),
            })),
            sse_capacity: SseCapacity::production(),
        };
        let app = build_authenticated_app(state).layer(MockConnectInfo(test_peer()));
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
                            "password": TEST_OWNER_PASSWORD,
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
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

    fn update_test_user_access(path: &Path, role: &str, status: &str) {
        let connection = Connection::open(path).unwrap();
        connection.busy_timeout(Duration::from_secs(1)).unwrap();
        assert_eq!(
            connection
                .execute(
                    "UPDATE users SET role = ?1, status = ?2, updated_at = ?3 WHERE username = 'owner'",
                    params![
                        role,
                        status,
                        chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
                    ],
                )
                .unwrap(),
            1
        );
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
        cookie_header: String,
        csrf_token: String,
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
                       projection_sequence, active_turn_id, owner_user_id
                   ) VALUES (?1, ?2, 'ready', ?3, ?3, 0, 0, NULL, ?4)"#,
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
                session_token_hash: session_token.digest().to_persistence(),
                csrf_hash: csrf_token.digest().to_persistence(),
                session_expires_at: expires_at,
            })
            .await
            .unwrap();
        TestIdentity {
            user_id: user_id.into(),
            cookie_header: format!(
                "{SESSION_COOKIE}={}; {CSRF_COOKIE}={}",
                session_token.expose_secret(),
                csrf_token.expose_secret()
            ),
            csrf_token: csrf_token.expose_secret().into(),
        }
    }

    fn insert_test_member(path: &Path, user_id: &str, username: &str) -> TestIdentity {
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
                r#"INSERT INTO auth_sessions(
                       token_hash, user_id, csrf_hash, created_at, expires_at, last_seen_at
                   ) VALUES (?1, ?2, ?3, ?4, ?5, ?4)"#,
                params![
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
        connection
            .execute_batch("DROP TRIGGER sessions_owner_is_write_once")
            .unwrap();
        assert_eq!(
            connection
                .execute(
                    "UPDATE sessions SET owner_user_id = ?1 WHERE id = ?2",
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
        connection
            .execute_batch("DROP TRIGGER runs_owner_is_write_once")
            .unwrap();
        assert_eq!(
            connection
                .execute(
                    "UPDATE runs SET owner_user_id = ?1 WHERE id = ?2",
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
