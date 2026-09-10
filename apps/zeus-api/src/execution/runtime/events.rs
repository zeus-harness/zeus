use serde_json::Value;
use sqlx::{FromRow, Postgres, Transaction};
use time::OffsetDateTime;
use uuid::Uuid;
use zeus_core::{
    ActorKind, ActorRef, EventEnvelope, EventId, RunId, SessionEvent, SessionEventKind, SessionId,
};

use super::{DurableRunExecutor, types::RuntimeFailure};
use crate::supervisor::ClaimedRun;

pub(super) async fn append_session_event(
    transaction: &mut Transaction<'_, Postgres>,
    run: &ClaimedRun,
    event_type: &str,
    payload: Value,
) -> Result<Uuid, RuntimeFailure> {
    let (event_id,): (Uuid,) = sqlx::query_as(
        "select event_id
         from zeus_private.append_session_event($1, $2, 'agent', null, $3, $4, $5)",
    )
    .bind(run.session_id)
    .bind(event_type)
    .bind(payload)
    .bind(run.run_id)
    .bind(1_i16)
    .fetch_one(&mut **transaction)
    .await?;
    Ok(event_id)
}

pub(super) async fn append_run_event_in_transaction(
    transaction: &mut Transaction<'_, Postgres>,
    run: &ClaimedRun,
    event_type: &str,
    payload: Value,
    session_event_id: Option<Uuid>,
) -> Result<Uuid, RuntimeFailure> {
    let (event_id,): (Uuid,) = sqlx::query_as(
        "select event_id
         from zeus_private.append_run_event($1, $2, $3, $4, $5)",
    )
    .bind(run.run_id)
    .bind(event_type)
    .bind(payload)
    .bind(session_event_id)
    .bind(1_i16)
    .fetch_one(&mut **transaction)
    .await?;
    Ok(event_id)
}

impl DurableRunExecutor {
    pub(super) async fn append_run_event(
        &self,
        run: &ClaimedRun,
        event_type: &str,
        payload: Value,
        session_event_id: Option<Uuid>,
    ) -> Result<(), RuntimeFailure> {
        let mut transaction = self.begin_fenced(run).await?;
        append_run_event_in_transaction(
            &mut transaction,
            run,
            event_type,
            payload,
            session_event_id,
        )
        .await?;
        transaction.commit().await?;
        Ok(())
    }

    pub(super) async fn begin_fenced<'a>(
        &'a self,
        run: &ClaimedRun,
    ) -> Result<Transaction<'a, Postgres>, RuntimeFailure> {
        let mut transaction = self.pool.begin().await?;
        let current: bool = sqlx::query_scalar("select zeus_private.lock_runtime_run($1, $2, $3)")
            .bind(run.run_id)
            .bind(&self.node_id)
            .bind(run.fence_token)
            .fetch_one(&mut *transaction)
            .await?;
        if !current {
            return Err(RuntimeFailure::StaleFence);
        }
        Ok(transaction)
    }
}

#[derive(Debug, FromRow)]
pub(super) struct StoredSessionEvent {
    id: Uuid,
    session_id: Uuid,
    run_id: Option<Uuid>,
    sequence: i64,
    schema_version: i16,
    event_type: String,
    actor_kind: String,
    actor_id: Option<Uuid>,
    payload: Value,
    occurred_at: OffsetDateTime,
}

impl StoredSessionEvent {
    pub(super) fn into_domain(self) -> Option<Result<SessionEvent, RuntimeFailure>> {
        let kind = match self.event_type.as_str() {
            "user_message" => required_string(&self.payload, "content")
                .map(|content| SessionEventKind::UserMessage { content }),
            "assistant_message" => required_string(&self.payload, "content")
                .map(|content| SessionEventKind::AssistantMessage { content }),
            "tool_call" => required_string(&self.payload, "call_id").and_then(|call_id| {
                required_string(&self.payload, "capability").map(|capability| {
                    SessionEventKind::ToolCall {
                        call_id,
                        capability,
                    }
                })
            }),
            "tool_result" => required_string(&self.payload, "call_id").map(|call_id| {
                SessionEventKind::ToolResult {
                    call_id,
                    result: self.payload.get("result").cloned().unwrap_or(Value::Null),
                    synthetic: self
                        .payload
                        .get("synthetic")
                        .and_then(Value::as_bool)
                        .unwrap_or(false),
                }
            }),
            "approval_result" => {
                let approval_id = self
                    .payload
                    .get("approval_id")
                    .and_then(Value::as_str)
                    .and_then(|value| Uuid::parse_str(value).ok())
                    .ok_or(RuntimeFailure::InvalidSession);
                let approved = self
                    .payload
                    .get("approved")
                    .and_then(Value::as_bool)
                    .ok_or(RuntimeFailure::InvalidSession);
                approval_id.and_then(|approval_id| {
                    approved.map(|approved| SessionEventKind::ApprovalResult {
                        approval_id,
                        approved,
                    })
                })
            }
            "steering_message" => required_string(&self.payload, "content")
                .map(|content| SessionEventKind::SteeringMessage { content }),
            "follow_up_message" => required_string(&self.payload, "content")
                .map(|content| SessionEventKind::FollowUpMessage { content }),
            _ => return None,
        };

        Some(kind.and_then(|kind| {
            let actor_kind = match self.actor_kind.as_str() {
                "user" => ActorKind::User,
                "service_account" => ActorKind::ServiceAccount,
                "agent" => ActorKind::Agent,
                "system" => ActorKind::System,
                _ => return Err(RuntimeFailure::InvalidSession),
            };
            let schema_version =
                u16::try_from(self.schema_version).map_err(|_| RuntimeFailure::InvalidSession)?;
            Ok(SessionEvent {
                session_id: SessionId::from_uuid(self.session_id),
                run_id: self.run_id.map(RunId::from_uuid),
                envelope: EventEnvelope {
                    id: EventId::from_uuid(self.id),
                    sequence: self.sequence,
                    schema_version,
                    event_type: self.event_type,
                    occurred_at: self.occurred_at,
                    actor: ActorRef {
                        kind: actor_kind,
                        id: self.actor_id,
                    },
                    payload: self.payload,
                },
                kind,
            })
        }))
    }
}

fn required_string(payload: &Value, key: &str) -> Result<String, RuntimeFailure> {
    payload
        .get(key)
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .ok_or(RuntimeFailure::InvalidSession)
}
