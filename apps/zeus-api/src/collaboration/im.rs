//! Organization-scoped messaging, independent of runtime Sessions.
#![allow(clippy::missing_errors_doc)]
use crate::{
    AppState,
    api_support::{ListCursor, PageQuery},
    auth::AuthContext,
    database::begin_tenant,
    error::ApiError,
};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    routing::get,
};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, Postgres, Transaction};
use time::OffsetDateTime;
use utoipa::ToSchema;
use uuid::Uuid;

#[derive(Serialize, ToSchema, FromRow)]
pub struct ImConversation {
    pub id: Uuid,
    pub organization_id: Uuid,
    pub kind: String,
    pub title: String,
    pub unread: i64,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}
#[derive(Serialize, ToSchema, FromRow)]
pub struct ImPerson {
    pub id: Uuid,
    pub display_name: String,
}
#[derive(Serialize, ToSchema, FromRow)]
pub struct ImParticipant {
    pub id: Uuid,
    pub display_name: String,
    pub organization_id: Uuid,
    pub role: String,
}
#[derive(Serialize, ToSchema, FromRow)]
pub struct ImMessage {
    pub id: Uuid,
    pub sequence: i64,
    pub sender_id: Option<Uuid>,
    pub sender_agent_id: Option<Uuid>,
    pub agent_run_id: Option<Uuid>,
    pub sender_organization_id: Uuid,
    pub sender_name: String,
    pub organization_name: String,
    pub content: String,
    pub reply_to: Option<Uuid>,
    pub mentions: Vec<Uuid>,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}
#[derive(Serialize, ToSchema)]
pub struct ImConversations {
    pub items: Vec<ImConversation>,
    pub next_cursor: Option<String>,
}
#[derive(Serialize, ToSchema)]
pub struct ImMessages {
    pub items: Vec<ImMessage>,
    pub next_cursor: Option<String>,
}
#[derive(Serialize, ToSchema)]
pub struct ImPeople {
    pub items: Vec<ImPerson>,
    pub next_cursor: Option<String>,
}
#[derive(Serialize, ToSchema)]
pub struct ImDetail {
    pub conversation: ImConversation,
    pub members: Vec<ImParticipant>,
    pub agents: Vec<super::im_agents::ImAgentMember>,
    pub calls: Vec<super::im_agents::ImAgentCall>,
}
#[derive(Serialize, ToSchema)]
pub struct ImId {
    pub id: Uuid,
}
#[derive(Deserialize, ToSchema)]
pub struct ImCreate {
    pub kind: String,
    pub title: String,
    pub participants: Vec<Uuid>,
    pub request_id: Uuid,
}
#[derive(Deserialize, ToSchema)]
pub struct ImSend {
    pub content: String,
    pub reply_to: Option<Uuid>,
    #[serde(default)]
    pub mentions: Vec<Uuid>,
    pub request_id: Uuid,
}
#[derive(Deserialize, ToSchema)]
pub struct ImChange {
    pub operation: String,
    pub value: Option<String>,
    pub target: Option<Uuid>,
}
#[derive(Deserialize, Default)]
pub struct ImDirectoryQuery {
    pub q: Option<String>,
    pub cursor: Option<String>,
}

pub(super) fn db_error(error: sqlx::Error) -> ApiError {
    match error
        .as_database_error()
        .and_then(sqlx::error::DatabaseError::code)
        .as_deref()
    {
        Some("42501") => ApiError::Forbidden,
        Some("22023" | "23505") => ApiError::Validation("invalid or conflicting IM request".into()),
        _ => ApiError::from(error),
    }
}
pub(super) async fn tenant<'a>(
    state: &'a AppState,
    auth: &AuthContext,
    org: Uuid,
) -> Result<Transaction<'a, Postgres>, ApiError> {
    if auth.organization_id != org
        || auth.user_id.is_none()
        || auth.tenant_access_grant_id.is_some()
    {
        return Err(ApiError::Forbidden);
    }
    let mut tx = begin_tenant(&state.platform.database, auth.tenant_scope(None)).await?;
    let allowed: bool = sqlx::query_scalar("select zeus_private.im_active_member($1,$2)")
        .bind(org)
        .bind(auth.user_id)
        .fetch_one(&mut *tx)
        .await?;
    if !allowed {
        return Err(ApiError::Forbidden);
    }
    Ok(tx)
}
const CONVERSATION_SELECT:&str="select c.id,c.organization_id,c.kind,case when c.kind='direct' then coalesce((select p.display_name from zeus_private.im_participants(c.id) p where p.id<>zeus_private.current_user_id() limit 1),c.title) else c.title end as title,c.created_at,
 (select count(*) from im_messages msg where msg.conversation_id=c.id and msg.sequence>m.last_read_sequence and (msg.sender_id is null or msg.sender_id<>m.user_id)) as unread
 from im_conversations c join im_members m on m.conversation_id=c.id and m.user_id=zeus_private.current_user_id() and m.left_at is null";

pub async fn list(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(org): Path<Uuid>,
    Query(query): Query<PageQuery>,
) -> Result<Json<ImConversations>, ApiError> {
    let mut tx = tenant(&state, &auth, org).await?;
    let cursor = query.decoded_cursor()?;
    let limit = query.limit()?;
    let mut items=sqlx::query_as::<_,ImConversation>(&format!("{CONVERSATION_SELECT} where ($1::timestamptz is null or (c.created_at,c.id)<($1,$2)) order by c.created_at desc,c.id desc limit $3"))
 .bind(cursor.map(ListCursor::created_at)).bind(cursor.map(ListCursor::id)).bind(limit+1).fetch_all(&mut *tx).await?;
    let next_cursor = if items.len() > usize::try_from(limit).unwrap_or(100) {
        items.pop();
        items
            .last()
            .map(|r| ListCursor::new(r.created_at, r.id).encode())
            .transpose()?
    } else {
        None
    };
    tx.commit().await?;
    Ok(Json(ImConversations { items, next_cursor }))
}
pub async fn create(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(org): Path<Uuid>,
    Json(input): Json<ImCreate>,
) -> Result<Json<ImId>, ApiError> {
    let mut tx = tenant(&state, &auth, org).await?;
    let id = sqlx::query_scalar("select zeus_private.im_create($1,$2,$3,$4,$5)")
        .bind(org)
        .bind(input.kind)
        .bind(input.title)
        .bind(input.participants)
        .bind(input.request_id)
        .fetch_one(&mut *tx)
        .await
        .map_err(db_error)?;
    tx.commit().await?;
    Ok(Json(ImId { id }))
}
pub async fn detail(
    State(state): State<AppState>,
    auth: AuthContext,
    Path((org, id)): Path<(Uuid, Uuid)>,
) -> Result<Json<ImDetail>, ApiError> {
    let mut tx = tenant(&state, &auth, org).await?;
    let conversation =
        sqlx::query_as::<_, ImConversation>(&format!("{CONVERSATION_SELECT} where c.id=$1"))
            .bind(id)
            .fetch_optional(&mut *tx)
            .await?
            .ok_or(ApiError::NotFound)?;
    let members = sqlx::query_as("select * from zeus_private.im_participants($1)")
        .bind(id)
        .fetch_all(&mut *tx)
        .await?;
    let agents = super::im_agents::members(&mut tx, id).await?;
    let calls = sqlx::query_as("select * from zeus_private.im_agent_calls($1)")
        .bind(id)
        .fetch_all(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(Json(ImDetail {
        conversation,
        members,
        agents,
        calls,
    }))
}
pub async fn messages(
    State(state): State<AppState>,
    auth: AuthContext,
    Path((org, id)): Path<(Uuid, Uuid)>,
    Query(query): Query<PageQuery>,
) -> Result<Json<ImMessages>, ApiError> {
    let mut tx = tenant(&state, &auth, org).await?;
    let visible: bool = sqlx::query_scalar("select zeus_private.im_visible($1)")
        .bind(id)
        .fetch_one(&mut *tx)
        .await?;
    if !visible {
        return Err(ApiError::NotFound);
    }
    let cursor = query.decoded_cursor()?;
    let limit = query.limit()?;
    let mut items=sqlx::query_as::<_,ImMessage>("select id,sequence,sender_id,sender_agent_id,agent_run_id,sender_organization_id,sender_name,organization_name,content,reply_to,mentions,created_at from im_messages where conversation_id=$1 and ($2::timestamptz is null or (created_at,id)<($2,$3)) order by created_at desc,id desc limit $4")
 .bind(id).bind(cursor.map(ListCursor::created_at)).bind(cursor.map(ListCursor::id)).bind(limit+1).fetch_all(&mut *tx).await?;
    let next_cursor = if items.len() > usize::try_from(limit).unwrap_or(100) {
        items.pop();
        items
            .last()
            .map(|r| ListCursor::new(r.created_at, r.id).encode())
            .transpose()?
    } else {
        None
    };
    items.reverse();
    tx.commit().await?;
    Ok(Json(ImMessages { items, next_cursor }))
}
pub async fn send(
    State(state): State<AppState>,
    auth: AuthContext,
    Path((org, id)): Path<(Uuid, Uuid)>,
    Json(input): Json<ImSend>,
) -> Result<Json<ImId>, ApiError> {
    let mut tx = tenant(&state, &auth, org).await?;
    let id = sqlx::query_scalar("select zeus_private.im_send($1,$2,$3,$4,$5)")
        .bind(id)
        .bind(input.request_id)
        .bind(input.content)
        .bind(input.reply_to)
        .bind(input.mentions)
        .fetch_one(&mut *tx)
        .await
        .map_err(db_error)?;
    tx.commit().await?;
    Ok(Json(ImId { id }))
}
pub async fn change(
    State(state): State<AppState>,
    auth: AuthContext,
    Path((org, id)): Path<(Uuid, Uuid)>,
    Json(input): Json<ImChange>,
) -> Result<axum::http::StatusCode, ApiError> {
    let mut tx = tenant(&state, &auth, org).await?;
    sqlx::query("select zeus_private.im_change($1,$2,$3,$4)")
        .bind(id)
        .bind(input.operation)
        .bind(input.value.unwrap_or_default())
        .bind(input.target)
        .execute(&mut *tx)
        .await
        .map_err(db_error)?;
    tx.commit().await?;
    Ok(axum::http::StatusCode::NO_CONTENT)
}
pub async fn directory(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(org): Path<Uuid>,
    Query(query): Query<ImDirectoryQuery>,
) -> Result<Json<ImPeople>, ApiError> {
    let mut tx = tenant(&state, &auth, org).await?;
    let cursor = PageQuery {
        cursor: query.cursor,
        limit: None,
    }
    .decoded_cursor()?;
    let search = query.q.unwrap_or_default();
    if search.chars().count() > 100 {
        return Err(ApiError::Validation("search is too long".into()));
    }
    let mut items: Vec<ImPerson> = sqlx::query_as("select * from zeus_private.im_people($1,$2,$3)")
        .bind(org)
        .bind(search)
        .bind(cursor.map(ListCursor::id))
        .fetch_all(&mut *tx)
        .await?;
    let next_cursor = if items.len() > 50 {
        items.pop();
        items
            .last()
            .map(|r| ListCursor::new(OffsetDateTime::UNIX_EPOCH, r.id).encode())
            .transpose()?
    } else {
        None
    };
    tx.commit().await?;
    Ok(Json(ImPeople { items, next_cursor }))
}
pub fn routes() -> Router<AppState> {
    Router::new()
        .route(
            "/api/v1/organizations/{organization_id}/im/conversations",
            get(list).post(create),
        )
        .route(
            "/api/v1/organizations/{organization_id}/im/conversations/{conversation_id}",
            get(detail).patch(change),
        )
        .route(
            "/api/v1/organizations/{organization_id}/im/conversations/{conversation_id}/messages",
            get(messages).post(send),
        )
        .route(
            "/api/v1/organizations/{organization_id}/im/people",
            get(directory),
        )
}
