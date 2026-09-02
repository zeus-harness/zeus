use sqlx::{PgPool, Postgres, Transaction};
use uuid::Uuid;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TenantScope {
    pub user_id: Option<Uuid>,
    pub session_id: Option<Uuid>,
    pub organization_id: Uuid,
    pub workspace_id: Option<Uuid>,
    pub tenant_access_grant_id: Option<Uuid>,
}

impl TenantScope {
    #[must_use]
    pub const fn organization(user_id: Option<Uuid>, organization_id: Uuid) -> Self {
        Self {
            user_id,
            session_id: None,
            organization_id,
            workspace_id: None,
            tenant_access_grant_id: None,
        }
    }

    #[must_use]
    pub const fn workspace(
        user_id: Option<Uuid>,
        organization_id: Uuid,
        workspace_id: Uuid,
    ) -> Self {
        Self {
            user_id,
            session_id: None,
            organization_id,
            workspace_id: Some(workspace_id),
            tenant_access_grant_id: None,
        }
    }
}

/// Starts a short tenant transaction and installs the RLS context with `SET LOCAL` semantics.
///
/// External HTTP, model, and capability calls must happen after this transaction is committed.
///
/// # Errors
///
/// Returns a database error when the transaction or tenant context cannot be created.
pub async fn begin_tenant(
    pool: &PgPool,
    scope: TenantScope,
) -> Result<Transaction<'_, Postgres>, sqlx::Error> {
    let mut transaction = pool.begin().await?;
    sqlx::query(
        "select set_config('zeus.user_id', $1, true), \
                set_config('zeus.session_id', $2, true), \
                set_config('zeus.organization_id', $3, true), \
                set_config('zeus.workspace_id', $4, true), \
                set_config('zeus.tenant_access_grant_id', $5, true)",
    )
    .bind(scope.user_id.map_or_else(String::new, |id| id.to_string()))
    .bind(
        scope
            .session_id
            .map_or_else(String::new, |id| id.to_string()),
    )
    .bind(scope.organization_id.to_string())
    .bind(
        scope
            .workspace_id
            .map_or_else(String::new, |id| id.to_string()),
    )
    .bind(
        scope
            .tenant_access_grant_id
            .map_or_else(String::new, |id| id.to_string()),
    )
    .execute(&mut *transaction)
    .await?;
    Ok(transaction)
}

/// Starts a user-scoped transaction for global account resources.
///
/// Organization and workspace settings remain empty, so tenant tables stay
/// inaccessible while user-level RLS policies can authorize the account owner.
///
/// # Errors
///
/// Returns a database error when the transaction or user context cannot be created.
pub async fn begin_user(
    pool: &PgPool,
    user_id: Uuid,
) -> Result<Transaction<'_, Postgres>, sqlx::Error> {
    let mut transaction = pool.begin().await?;
    sqlx::query(
        "select set_config('zeus.user_id', $1, true),
                set_config('zeus.session_id', '', true),
                set_config('zeus.organization_id', '', true),
                set_config('zeus.workspace_id', '', true),
                set_config('zeus.tenant_access_grant_id', '', true)",
    )
    .bind(user_id.to_string())
    .execute(&mut *transaction)
    .await?;
    Ok(transaction)
}

#[cfg(test)]
mod tests {
    use uuid::Uuid;

    use super::TenantScope;

    #[test]
    fn workspace_scope_keeps_all_rls_identifiers() {
        let user_id = Uuid::now_v7();
        let organization_id = Uuid::now_v7();
        let workspace_id = Uuid::now_v7();
        let scope = TenantScope::workspace(Some(user_id), organization_id, workspace_id);

        assert_eq!(scope.user_id, Some(user_id));
        assert_eq!(scope.session_id, None);
        assert_eq!(scope.organization_id, organization_id);
        assert_eq!(scope.workspace_id, Some(workspace_id));
        assert_eq!(scope.tenant_access_grant_id, None);
    }
}
