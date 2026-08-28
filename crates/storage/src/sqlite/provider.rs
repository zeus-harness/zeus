//! Account-scoped selection of startup-registered reply providers.
//!
//! This module persists only manifest-safe metadata. Provider endpoints,
//! credentials, and SecretRefs remain owned by the service process.

use super::*;
use crate::{
    AccountReplyProviderCommit, AccountReplyProviderState, AccountReplyProviderUpdateResult,
};
use protocol::AssistantReplyKind;

const ACCOUNT_REPLY_PROVIDER_MAX_REVISIONS: u64 = 256;

fn reply_kind_to_db(kind: &AssistantReplyKind) -> &'static str {
    match kind {
        AssistantReplyKind::Model => "model",
        AssistantReplyKind::NonModelFallback => "non_model_fallback",
    }
}

fn decode_reply_kind(value: &str) -> Result<AssistantReplyKind, StorageError> {
    match value {
        "model" => Ok(AssistantReplyKind::Model),
        "non_model_fallback" => Ok(AssistantReplyKind::NonModelFallback),
        other => Err(StorageError::CorruptData(format!(
            "unsupported account reply provider kind `{other}`"
        ))),
    }
}

fn validate_binding(
    provider_id: &str,
    model: Option<&str>,
    reply_kind: &AssistantReplyKind,
) -> Result<(), StorageError> {
    protocol::validate_reply_provider_id(provider_id).map_err(|error| {
        StorageError::InvalidAccountReplyProvider(format!("provider ID {error}"))
    })?;
    if let Some(model) = model {
        protocol::validate_reply_model_id(model).map_err(|error| {
            StorageError::InvalidAccountReplyProvider(format!("model ID {error}"))
        })?;
    }
    match (reply_kind, model) {
        (AssistantReplyKind::Model, Some(_)) | (AssistantReplyKind::NonModelFallback, None) => {
            Ok(())
        }
        (AssistantReplyKind::Model, None) => Err(StorageError::InvalidAccountReplyProvider(
            "a model provider must name its model".into(),
        )),
        (AssistantReplyKind::NonModelFallback, Some(_)) => {
            Err(StorageError::InvalidAccountReplyProvider(
                "a non-model fallback cannot name a model".into(),
            ))
        }
    }
}

pub(super) fn validate_startup_default(
    account_id: &AccountId,
    default: &AccountReplyProviderState,
) -> Result<(), StorageError> {
    validate_binding(
        &default.provider_id,
        default.model.as_deref(),
        &default.reply_kind,
    )?;
    if &default.account_id != account_id
        || default.revision != 0
        || default.updated_by_user_id.is_some()
        || default.updated_by_membership_revision.is_some()
        || default.updated_at.is_some()
    {
        return Err(StorageError::InvalidAccountReplyProvider(
            "the startup default must be an implicit revision-zero binding for the requested account"
                .into(),
        ));
    }
    Ok(())
}

pub(super) fn query_account_reply_provider(
    connection: &Connection,
    account_id: &AccountId,
    startup_default: AccountReplyProviderState,
) -> Result<AccountReplyProviderState, StorageError> {
    validate_startup_default(account_id, &startup_default)?;
    let stored = connection
        .query_row(
            r#"SELECT revision, provider_id, model, reply_kind,
                      updated_by_user_id, updated_by_membership_revision, updated_at
               FROM account_reply_provider_configs WHERE account_id = ?1"#,
            [account_id.as_str()],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, String>(6)?,
                ))
            },
        )
        .optional()?;
    let Some((revision, provider_id, model, reply_kind, actor, actor_revision, updated_at)) =
        stored
    else {
        return Ok(startup_default);
    };
    let reply_kind = decode_reply_kind(&reply_kind)?;
    validate_binding(&provider_id, model.as_deref(), &reply_kind).map_err(|error| {
        StorageError::CorruptData(format!(
            "account reply provider `{}` is invalid: {error}",
            account_id
        ))
    })?;
    Ok(AccountReplyProviderState {
        account_id: account_id.clone(),
        revision: i64_to_u64(revision, "account reply provider revision")?,
        provider_id,
        model,
        reply_kind,
        updated_by_user_id: Some(actor),
        updated_by_membership_revision: Some(decode_membership_revision(actor_revision)?),
        updated_at: Some(updated_at),
    })
}

pub(super) fn query_account_reply_provider_for_actor(
    connection: &Connection,
    context: &AuthzContext,
    startup_default: AccountReplyProviderState,
) -> Result<AccountReplyProviderState, StorageError> {
    require_current_authority(connection, context, AccountCapability::Reply)?;
    query_account_reply_provider(connection, &context.account_id, startup_default)
}

fn provider_fingerprint(
    expected_revision: u64,
    provider_id: &str,
    model: Option<&str>,
    reply_kind: &AssistantReplyKind,
) -> Result<String, StorageError> {
    Ok(serde_json::to_string(&json!({
        "expected_revision": expected_revision,
        "provider_id": provider_id,
        "model": model,
        "reply_kind": reply_kind_to_db(reply_kind),
    }))?)
}

pub(super) fn replace_account_reply_provider(
    connection: &mut Connection,
    context: &AuthzContext,
    commit: AccountReplyProviderCommit,
    limits: &StorageLimits,
    physical_limits: &SqlitePhysicalLimits,
) -> Result<AccountReplyProviderUpdateResult, StorageError> {
    validate_binding(
        &commit.provider_id,
        commit.model.as_deref(),
        &commit.reply_kind,
    )?;
    let key = normalized_key(&commit.idempotency_key)?.to_owned();
    let request_fingerprint = provider_fingerprint(
        commit.expected_revision,
        &commit.provider_id,
        commit.model.as_deref(),
        &commit.reply_kind,
    )?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    require_current_authority(&transaction, context, AccountCapability::AccountAdmin)?;

    let stored_receipt = transaction
        .query_row(
            r#"SELECT actor_membership_revision, request_fingerprint,
                      provider_revision, provider_id, model, reply_kind, created_at
               FROM account_reply_provider_receipts
               WHERE account_id = ?1 AND actor_user_id = ?2 AND idempotency_key = ?3"#,
            params![context.account_id.as_str(), context.user_id, key],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, Option<String>>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                ))
            },
        )
        .optional()?;
    if let Some((actor_revision, fingerprint, revision, provider_id, model, kind, created_at)) =
        stored_receipt
    {
        if decode_membership_revision(actor_revision)? != context.membership_revision
            || fingerprint != request_fingerprint
            || provider_id != commit.provider_id
            || model != commit.model
            || kind != reply_kind_to_db(&commit.reply_kind)
        {
            return Err(StorageError::IdempotencyConflict);
        }
        let revision = i64_to_u64(revision, "account reply provider receipt revision")?;
        let head: i64 = transaction.query_row(
            "SELECT revision FROM account_reply_provider_configs WHERE account_id = ?1",
            [context.account_id.as_str()],
            |row| row.get(0),
        )?;
        if i64_to_u64(head, "account reply provider head revision")? < revision {
            return Err(StorageError::CorruptData(
                "account reply provider receipt is ahead of the configuration head".into(),
            ));
        }
        transaction.commit()?;
        return Ok(AccountReplyProviderUpdateResult {
            provider: AccountReplyProviderState {
                account_id: context.account_id.clone(),
                revision,
                provider_id,
                model,
                reply_kind: decode_reply_kind(&kind)?,
                updated_by_user_id: Some(context.user_id.clone()),
                updated_by_membership_revision: Some(context.membership_revision),
                updated_at: Some(created_at),
            },
            replayed: true,
        });
    }

    let current = transaction
        .query_row(
            r#"SELECT revision, provider_id, model, reply_kind
               FROM account_reply_provider_configs WHERE account_id = ?1"#,
            [context.account_id.as_str()],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, String>(3)?,
                ))
            },
        )
        .optional()?;
    let current_revision = current
        .as_ref()
        .map(|row| i64_to_u64(row.0, "account reply provider revision"))
        .transpose()?
        .unwrap_or(0);
    if current_revision != commit.expected_revision {
        return Err(StorageError::AccountReplyProviderRevisionConflict);
    }
    if current
        .as_ref()
        .is_some_and(|(_, provider_id, model, kind)| {
            provider_id == &commit.provider_id
                && model == &commit.model
                && kind == reply_kind_to_db(&commit.reply_kind)
        })
    {
        return Err(StorageError::InvalidAccountReplyProvider(
            "the requested provider is already active".into(),
        ));
    }
    if current_revision >= ACCOUNT_REPLY_PROVIDER_MAX_REVISIONS {
        return Err(StorageError::StorageQuotaExceeded);
    }
    let next_revision = current_revision
        .checked_add(1)
        .ok_or(StorageError::IntegerOutOfRange(
            "account reply provider revision",
        ))?;
    require_connection_physical_capacity(
        &transaction,
        physical_limits,
        PhysicalCapacityGate::Admission,
    )?;
    let timestamp = now();
    prepare_account_audit_admission(
        &transaction,
        context.account_id.as_str(),
        AuditAdmission::General,
        limits,
        &timestamp,
    )?;
    let next_revision_sql = u64_to_i64(next_revision, "account reply provider revision")?;
    let actor_revision_sql = u64_to_i64(
        context.membership_revision.get(),
        "account reply provider membership revision",
    )?;
    let kind = reply_kind_to_db(&commit.reply_kind);
    let changed = if current_revision == 0 {
        transaction.execute(
            r#"INSERT INTO account_reply_provider_configs(
                   account_id, revision, provider_id, model, reply_kind,
                   updated_by_user_id, updated_by_membership_revision, updated_at
               ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)"#,
            params![
                context.account_id.as_str(),
                next_revision_sql,
                commit.provider_id,
                commit.model,
                kind,
                context.user_id,
                actor_revision_sql,
                timestamp,
            ],
        )?
    } else {
        transaction.execute(
            r#"UPDATE account_reply_provider_configs
               SET revision = ?1, provider_id = ?2, model = ?3, reply_kind = ?4,
                   updated_by_user_id = ?5, updated_by_membership_revision = ?6,
                   updated_at = ?7
               WHERE account_id = ?8 AND revision = ?9"#,
            params![
                next_revision_sql,
                commit.provider_id,
                commit.model,
                kind,
                context.user_id,
                actor_revision_sql,
                timestamp,
                context.account_id.as_str(),
                u64_to_i64(current_revision, "account reply provider expected revision")?,
            ],
        )?
    };
    if changed != 1 {
        return Err(StorageError::ConcurrentModification);
    }
    transaction.execute(
        r#"INSERT INTO account_reply_provider_receipts(
               account_id, actor_user_id, actor_membership_revision,
               idempotency_key, request_fingerprint, provider_revision,
               provider_id, model, reply_kind, created_at
           ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)"#,
        params![
            context.account_id.as_str(),
            context.user_id,
            actor_revision_sql,
            key,
            request_fingerprint,
            next_revision_sql,
            commit.provider_id,
            commit.model,
            kind,
            timestamp,
        ],
    )?;
    append_account_audit_event(
        &transaction,
        context.account_id.as_str(),
        AccountAuditEventInput {
            actor_user_id: Some(&context.user_id),
            action: "account.reply_provider.updated",
            target_kind: "reply_provider",
            target_id: &commit.provider_id,
            metadata: json!({
                "previous_revision": current_revision,
                "revision": next_revision,
                "provider_id": commit.provider_id,
                "model": commit.model,
                "reply_kind": kind,
            }),
        },
        &timestamp,
    )?;
    let provider = AccountReplyProviderState {
        account_id: context.account_id.clone(),
        revision: next_revision,
        provider_id: commit.provider_id,
        model: commit.model,
        reply_kind: commit.reply_kind,
        updated_by_user_id: Some(context.user_id.clone()),
        updated_by_membership_revision: Some(context.membership_revision),
        updated_at: Some(timestamp),
    };
    transaction.commit()?;
    Ok(AccountReplyProviderUpdateResult {
        provider,
        replayed: false,
    })
}

pub(super) fn verify_account_reply_provider_integrity(
    connection: &Connection,
) -> Result<(), StorageError> {
    let mut configs = connection.prepare(
        r#"SELECT account_id, revision, provider_id, model, reply_kind
           FROM account_reply_provider_configs ORDER BY account_id"#,
    )?;
    let rows = configs
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, Option<String>>(3)?,
                row.get::<_, String>(4)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    for (account_id, revision, provider_id, model, kind) in rows {
        let revision = i64_to_u64(revision, "account reply provider revision")?;
        let reply_kind = decode_reply_kind(&kind)?;
        validate_binding(&provider_id, model.as_deref(), &reply_kind).map_err(|error| {
            StorageError::CorruptData(format!(
                "account reply provider `{account_id}` is invalid: {error}"
            ))
        })?;
        if revision == 0 || revision > ACCOUNT_REPLY_PROVIDER_MAX_REVISIONS {
            return Err(StorageError::CorruptData(format!(
                "account reply provider `{account_id}` has invalid revision {revision}"
            )));
        }
        let (count, minimum, maximum): (i64, Option<i64>, Option<i64>) = connection.query_row(
            r#"SELECT COUNT(*), MIN(provider_revision), MAX(provider_revision)
               FROM account_reply_provider_receipts WHERE account_id = ?1"#,
            [&account_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )?;
        if i64_to_u64(count, "account reply provider receipt count")? != revision
            || minimum != Some(1)
            || maximum
                != Some(u64_to_i64(
                    revision,
                    "account reply provider maximum receipt revision",
                )?)
        {
            return Err(StorageError::CorruptData(format!(
                "account reply provider `{account_id}` history is not contiguous"
            )));
        }
        let head_matches: i64 = connection.query_row(
            r#"SELECT EXISTS(
                   SELECT 1
                   FROM account_reply_provider_receipts receipt
                   JOIN account_reply_provider_configs config
                     ON config.account_id = receipt.account_id
                    AND config.revision = receipt.provider_revision
                    AND config.provider_id = receipt.provider_id
                    AND config.model IS receipt.model
                    AND config.reply_kind = receipt.reply_kind
                    AND config.updated_by_user_id = receipt.actor_user_id
                    AND config.updated_by_membership_revision = receipt.actor_membership_revision
                    AND config.updated_at = receipt.created_at
                   WHERE receipt.account_id = ?1 AND receipt.provider_revision = ?2
                     AND receipt.provider_id = ?3 AND receipt.model IS ?4
                     AND receipt.reply_kind = ?5
               )"#,
            params![
                account_id,
                u64_to_i64(revision, "account reply provider head revision")?,
                provider_id,
                model,
                kind,
            ],
            |row| row.get(0),
        )?;
        if head_matches != 1 {
            return Err(StorageError::CorruptData(format!(
                "account reply provider `{account_id}` head disagrees with its receipt"
            )));
        }

        let mut receipts = connection.prepare(
            r#"SELECT provider_revision, request_fingerprint, provider_id, model,
                      reply_kind, actor_membership_revision
               FROM account_reply_provider_receipts
               WHERE account_id = ?1 ORDER BY provider_revision"#,
        )?;
        let history = receipts
            .query_map([&account_id], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, Option<String>>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, i64>(5)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        for (revision, fingerprint, provider_id, model, kind, actor_revision) in history {
            let revision = i64_to_u64(revision, "account reply provider receipt revision")?;
            let reply_kind = decode_reply_kind(&kind)?;
            validate_binding(&provider_id, model.as_deref(), &reply_kind).map_err(|error| {
                StorageError::CorruptData(format!(
                    "account reply provider `{account_id}` receipt {revision} is invalid: {error}"
                ))
            })?;
            decode_membership_revision(actor_revision)?;
            let expected = provider_fingerprint(
                revision.checked_sub(1).ok_or_else(|| {
                    StorageError::CorruptData(
                        "account reply provider receipt revision cannot be zero".into(),
                    )
                })?,
                &provider_id,
                model.as_deref(),
                &reply_kind,
            )?;
            if fingerprint != expected {
                return Err(StorageError::CorruptData(format!(
                    "account reply provider `{account_id}` receipt {revision} has an invalid fingerprint"
                )));
            }
        }
    }
    let orphan_receipts: i64 = connection.query_row(
        r#"SELECT COUNT(*)
           FROM account_reply_provider_receipts receipt
           LEFT JOIN account_reply_provider_configs config
             ON config.account_id = receipt.account_id
           WHERE config.account_id IS NULL"#,
        [],
        |row| row.get(0),
    )?;
    if orphan_receipts != 0 {
        return Err(StorageError::CorruptData(
            "one or more account reply provider receipts have no configuration head".into(),
        ));
    }
    Ok(())
}
