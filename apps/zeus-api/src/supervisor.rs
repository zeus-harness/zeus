use std::{
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use async_trait::async_trait;
use serde_json::{Value, json};
use sqlx::{FromRow, PgPool};
use tokio::{sync::Semaphore, task::JoinSet, time::Instant};
use tokio_util::sync::CancellationToken;
use tracing::{Instrument, error, info, info_span, warn};
use uuid::Uuid;

#[derive(Default)]
pub struct SupervisorMetrics {
    claimed: AtomicU64,
    finished: AtomicU64,
    failed: AtomicU64,
    active: AtomicU64,
    queue_depth: AtomicU64,
    http_requests: AtomicU64,
    http_inflight: AtomicU64,
}

impl SupervisorMetrics {
    #[must_use]
    pub fn claimed(&self) -> u64 {
        self.claimed.load(Ordering::Relaxed)
    }

    #[must_use]
    pub fn finished(&self) -> u64 {
        self.finished.load(Ordering::Relaxed)
    }

    #[must_use]
    pub fn failed(&self) -> u64 {
        self.failed.load(Ordering::Relaxed)
    }

    #[must_use]
    pub fn active(&self) -> u64 {
        self.active.load(Ordering::Relaxed)
    }

    #[must_use]
    pub fn queue_depth(&self) -> u64 {
        self.queue_depth.load(Ordering::Relaxed)
    }

    #[must_use]
    pub fn http_requests(&self) -> u64 {
        self.http_requests.load(Ordering::Relaxed)
    }

    #[must_use]
    pub fn http_inflight(&self) -> u64 {
        self.http_inflight.load(Ordering::Relaxed)
    }

    pub(crate) fn begin_http_request(self: &Arc<Self>) -> HttpRequestGuard {
        self.http_inflight.fetch_add(1, Ordering::Relaxed);
        HttpRequestGuard {
            metrics: Arc::clone(self),
        }
    }

    fn begin_active(self: &Arc<Self>) -> ActiveRunGuard {
        self.active.fetch_add(1, Ordering::Relaxed);
        ActiveRunGuard {
            metrics: Arc::clone(self),
        }
    }

    fn set_queue_depth(&self, depth: i64) {
        self.queue_depth
            .store(u64::try_from(depth).unwrap_or(u64::MAX), Ordering::Relaxed);
    }
}

struct ActiveRunGuard {
    metrics: Arc<SupervisorMetrics>,
}

impl Drop for ActiveRunGuard {
    fn drop(&mut self) {
        self.metrics.active.fetch_sub(1, Ordering::Relaxed);
    }
}

pub(crate) struct HttpRequestGuard {
    metrics: Arc<SupervisorMetrics>,
}

impl Drop for HttpRequestGuard {
    fn drop(&mut self) {
        self.metrics.http_inflight.fetch_sub(1, Ordering::Relaxed);
        self.metrics.http_requests.fetch_add(1, Ordering::Relaxed);
    }
}

#[derive(Clone, Debug, FromRow)]
pub struct ClaimedRun {
    pub run_id: Uuid,
    pub organization_id: Uuid,
    pub workspace_id: Uuid,
    pub session_id: Uuid,
    pub workflow_version_id: Uuid,
    pub fence_token: i64,
    pub attempt_number: i32,
}

#[derive(Debug)]
pub enum RunOutcome {
    Succeeded(Value),
    WaitingApproval,
    WaitingChild,
    Failed { code: String, detail: String },
    Canceled,
}

#[async_trait]
pub trait RunExecutor: Send + Sync + 'static {
    async fn execute(&self, run: &ClaimedRun, cancel: CancellationToken) -> RunOutcome;
}

pub struct ExecutionSupervisor<E> {
    pool: PgPool,
    executor: Arc<E>,
    node_id: String,
    lease_duration: Duration,
    poll_interval: Duration,
    capacity: Arc<Semaphore>,
    shutdown: CancellationToken,
    metrics: Arc<SupervisorMetrics>,
}

impl<E> ExecutionSupervisor<E>
where
    E: RunExecutor,
{
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn new(
        pool: PgPool,
        executor: Arc<E>,
        node_id: String,
        lease_duration: Duration,
        poll_interval: Duration,
        concurrency: usize,
        shutdown: CancellationToken,
        metrics: Arc<SupervisorMetrics>,
    ) -> Self {
        Self {
            pool,
            executor,
            node_id,
            lease_duration,
            poll_interval,
            capacity: Arc::new(Semaphore::new(concurrency)),
            shutdown,
            metrics,
        }
    }

    pub async fn run(self) {
        let mut tasks = JoinSet::new();
        info!(node_id = %self.node_id, "execution supervisor started");

        loop {
            tokio::select! {
                () = self.shutdown.cancelled() => break,
                Some(result) = tasks.join_next(), if !tasks.is_empty() => {
                    if let Err(error) = result {
                        error!(%error, "run task crashed");
                    }
                }
                () = tokio::time::sleep(self.poll_interval) => {
                    let Ok(permit) = Arc::clone(&self.capacity).try_acquire_owned() else {
                        continue;
                    };
                    match claim_run(&self.pool, &self.node_id, self.lease_duration).await {
                        Ok(Some(run)) => {
                            self.metrics.claimed.fetch_add(1, Ordering::Relaxed);
                            let pool = self.pool.clone();
                            let executor = Arc::clone(&self.executor);
                            let node_id = self.node_id.clone();
                            let metrics = Arc::clone(&self.metrics);
                            let lease_duration = self.lease_duration;
                            let span = info_span!(
                                "zeus.run",
                                run_id = %run.run_id,
                                organization_id = %run.organization_id,
                                workspace_id = %run.workspace_id,
                                session_id = %run.session_id,
                                attempt_number = run.attempt_number,
                                fence_token = run.fence_token,
                            );
                            tasks.spawn(async move {
                                let _permit = permit;
                                let _active = metrics.begin_active();
                                let outcome = execute_with_lease(
                                    &pool,
                                    &node_id,
                                    &run,
                                    lease_duration,
                                    executor.as_ref(),
                                )
                                .await;
                                let Some(outcome) = outcome else {
                                    metrics.failed.fetch_add(1, Ordering::Relaxed);
                                    return;
                                };
                                if let Err(error) = finish_run(&pool, &node_id, &run, outcome).await {
                                    metrics.failed.fetch_add(1, Ordering::Relaxed);
                                    warn!(run_id = %run.run_id, %error, "failed to commit run outcome");
                                } else {
                                    metrics.finished.fetch_add(1, Ordering::Relaxed);
                                }
                            }.instrument(span));
                        }
                        Ok(None) => drop(permit),
                        Err(error) => {
                            drop(permit);
                            warn!(%error, "run claim failed");
                        }
                    }
                    match ready_queue_depth(&self.pool).await {
                        Ok(depth) => self.metrics.set_queue_depth(depth),
                        Err(error) => warn!(%error, "run queue depth query failed"),
                    }
                }
            }
        }

        info!(node_id = %self.node_id, active = tasks.len(), "execution supervisor stopping");
        let grace = tokio::time::sleep(Duration::from_mins(1));
        tokio::pin!(grace);
        loop {
            tokio::select! {
                () = &mut grace => {
                    tasks.abort_all();
                    break;
                }
                result = tasks.join_next() => {
                    if result.is_none() {
                        break;
                    }
                }
            }
        }
    }
}

async fn execute_with_lease<E>(
    pool: &PgPool,
    node_id: &str,
    run: &ClaimedRun,
    lease_duration: Duration,
    executor: &E,
) -> Option<RunOutcome>
where
    E: RunExecutor,
{
    let cancel = CancellationToken::new();
    let execution = executor.execute(run, cancel.clone());
    tokio::pin!(execution);

    let heartbeat_interval = heartbeat_interval(lease_duration);
    let mut heartbeat = tokio::time::interval(heartbeat_interval);
    heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    heartbeat.tick().await;
    let mut cancellation_check = tokio::time::interval(Duration::from_secs(1));
    cancellation_check.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    cancellation_check.tick().await;
    let mut last_heartbeat = Instant::now();

    loop {
        tokio::select! {
            outcome = &mut execution => return Some(outcome),
            _ = heartbeat.tick() => {
                match heartbeat_run(pool, node_id, run, lease_duration).await {
                    Ok(true) => last_heartbeat = Instant::now(),
                    Ok(false) => {
                        cancel.cancel();
                        warn!(run_id = %run.run_id, "run lease or fence is stale; discarding executor outcome");
                        return None;
                    }
                    Err(error) => {
                        warn!(run_id = %run.run_id, %error, "run heartbeat failed");
                        if last_heartbeat.elapsed() >= lease_duration {
                            cancel.cancel();
                            return None;
                        }
                    }
                }

            }
            _ = cancellation_check.tick() => {
                match is_cancel_requested(pool, run.run_id).await {
                    Ok(true) => cancel.cancel(),
                    Ok(false) => {}
                    Err(error) => {
                        warn!(run_id = %run.run_id, %error, "run cancellation check failed");
                    }
                }
            }
        }
    }
}

fn heartbeat_interval(lease_duration: Duration) -> Duration {
    let interval = lease_duration / 3;
    interval.clamp(Duration::from_secs(1), Duration::from_secs(30))
}

async fn claim_run(
    pool: &PgPool,
    node_id: &str,
    lease_duration: Duration,
) -> Result<Option<ClaimedRun>, sqlx::Error> {
    let lease_seconds = i32::try_from(lease_duration.as_secs()).unwrap_or(i32::MAX);
    sqlx::query_as::<_, ClaimedRun>("select * from zeus_private.claim_run($1, $2)")
        .bind(node_id)
        .bind(lease_seconds)
        .fetch_optional(pool)
        .await
}

async fn ready_queue_depth(pool: &PgPool) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar(
        "select count(*)::bigint
         from runs
         where status = 'queued' and available_at <= now() and cancel_requested_at is null",
    )
    .fetch_one(pool)
    .await
}

async fn heartbeat_run(
    pool: &PgPool,
    node_id: &str,
    run: &ClaimedRun,
    lease_duration: Duration,
) -> Result<bool, sqlx::Error> {
    let lease_seconds = i32::try_from(lease_duration.as_secs()).unwrap_or(i32::MAX);
    sqlx::query_scalar("select zeus_private.heartbeat_run($1, $2, $3, $4)")
        .bind(run.run_id)
        .bind(node_id)
        .bind(run.fence_token)
        .bind(lease_seconds)
        .fetch_one(pool)
        .await
}

async fn is_cancel_requested(pool: &PgPool, run_id: Uuid) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar("select zeus_private.is_run_cancel_requested($1)")
        .bind(run_id)
        .fetch_one(pool)
        .await
}

async fn finish_run(
    pool: &PgPool,
    node_id: &str,
    run: &ClaimedRun,
    outcome: RunOutcome,
) -> anyhow::Result<()> {
    let (status, result, code, detail) = match outcome {
        RunOutcome::Succeeded(result) => ("succeeded", Some(result), None, None),
        RunOutcome::WaitingApproval => ("waiting_approval", None, None, None),
        RunOutcome::WaitingChild => ("waiting_child", None, None, None),
        RunOutcome::Failed { code, detail } => ("failed", None, Some(code), Some(detail)),
        RunOutcome::Canceled => ("canceled", Some(json!({ "canceled": true })), None, None),
    };

    let committed: bool =
        sqlx::query_scalar("select zeus_private.finish_run($1, $2, $3, $4, $5, $6, $7)")
            .bind(run.run_id)
            .bind(node_id)
            .bind(run.fence_token)
            .bind(status)
            .bind(result)
            .bind(code)
            .bind(detail)
            .fetch_one(pool)
            .await?;

    anyhow::ensure!(committed, "stale lease or fence token");
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{sync::Arc, time::Duration};

    use super::{SupervisorMetrics, heartbeat_interval};

    #[test]
    fn heartbeat_is_bounded_for_short_and_long_leases() {
        assert_eq!(
            heartbeat_interval(Duration::from_secs(2)),
            Duration::from_secs(1)
        );
        assert_eq!(
            heartbeat_interval(Duration::from_secs(30)),
            Duration::from_secs(10)
        );
        assert_eq!(
            heartbeat_interval(Duration::from_mins(5)),
            Duration::from_secs(30)
        );
    }

    #[test]
    fn http_request_guard_tracks_inflight_and_completed_requests() {
        let metrics = Arc::new(SupervisorMetrics::default());
        let first = metrics.begin_http_request();
        assert_eq!(metrics.http_inflight(), 1);
        assert_eq!(metrics.http_requests(), 0);

        {
            let _second = metrics.begin_http_request();
            assert_eq!(metrics.http_inflight(), 2);
        }
        assert_eq!(metrics.http_inflight(), 1);
        assert_eq!(metrics.http_requests(), 1);

        drop(first);
        assert_eq!(metrics.http_inflight(), 0);
        assert_eq!(metrics.http_requests(), 2);
    }
}
