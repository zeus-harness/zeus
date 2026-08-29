use sqlx::{PgPool, Postgres, Transaction};
use uuid::Uuid;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TenantScope {
    pub user_id: Option<Uuid>,
    pub organization_id: Uuid,
    pub workspace_id: Option<Uuid>,
}

impl TenantScope {
    #[must_use]
    pub const fn organization(user_id: Option<Uuid>, organization_id: Uuid) -> Self {
        Self {
            user_id,
            organization_id,
            workspace_id: None,
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
            organization_id,
            workspace_id: Some(workspace_id),
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
                set_config('zeus.organization_id', $2, true), \
                set_config('zeus.workspace_id', $3, true)",
    )
    .bind(scope.user_id.map_or_else(String::new, |id| id.to_string()))
    .bind(scope.organization_id.to_string())
    .bind(
        scope
            .workspace_id
            .map_or_else(String::new, |id| id.to_string()),
    )
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
        assert_eq!(scope.organization_id, organization_id);
        assert_eq!(scope.workspace_id, Some(workspace_id));
    }
}
