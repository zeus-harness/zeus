use super::{
    DurableRunExecutor,
    types::{RunPlan, RuntimeFailure},
};
use crate::{
    execution::code_workspace::{CodeScope, RepositoryBinding},
    supervisor::ClaimedRun,
};
use serde_json::json;
use uuid::Uuid;

fn scope(run: &ClaimedRun) -> CodeScope {
    CodeScope {
        organization_id: run.organization_id,
        workspace_id: run.workspace_id,
        run_id: run.run_id,
        fence: run.fence_token,
    }
}
impl DurableRunExecutor {
    pub(super) async fn prepare_code(
        &self,
        run: &ClaimedRun,
        plan: &RunPlan,
    ) -> Result<Option<RepositoryBinding>, RuntimeFailure> {
        let Some(value) = &plan.code_repository else {
            return Ok(None);
        };
        let binding: RepositoryBinding = serde_json::from_value(value.clone())
            .map_err(|_| RuntimeFailure::InvalidConfiguration("invalid_code_repository"))?;
        let storage = self
            .code_storage
            .as_ref()
            .ok_or(RuntimeFailure::InvalidConfiguration(
                "code_storage_not_configured",
            ))?;
        // Check the lease before touching this attempt's private directory.
        let mut transaction = self.begin_fenced(run).await?;
        let eligible: bool = sqlx::query_scalar("select lease_expires_at > clock_timestamp() and cancel_requested_at is null from runs where id = $1")
            .bind(run.run_id).fetch_one(&mut *transaction).await?;
        if !eligible {
            return Err(RuntimeFailure::StaleFence);
        }
        transaction.commit().await?;
        let checkpoint: Option<String> = sqlx::query_scalar("select checkpoint_commit from run_code_checkpoints
            where run_id = $1 and organization_id = $2 and workspace_id = $3 order by created_at desc, id desc limit 1")
            .bind(run.run_id).bind(run.organization_id).bind(run.workspace_id).fetch_optional(&self.pool).await?;
        storage
            .prepare(scope(run), &binding, checkpoint.as_deref())
            .await
            .map_err(|_| RuntimeFailure::InvalidConfiguration("code_prepare_failed"))?;
        self.append_run_event(
            run,
            "code.prepared",
            json!({"repository_id":binding.repository_id,
            "base_commit":binding.commit, "restored":checkpoint.is_some()}),
            None,
        )
        .await?;
        Ok(Some(binding))
    }
    pub(super) async fn checkpoint_code(
        &self,
        run: &ClaimedRun,
        binding: &RepositoryBinding,
    ) -> Result<(), RuntimeFailure> {
        self.save_code_checkpoint(run, binding).await?;
        self.code_storage
            .as_ref()
            .ok_or(RuntimeFailure::InvalidConfiguration(
                "code_storage_not_configured",
            ))?
            .release(scope(run), binding)
            .await
            .map_err(|_| RuntimeFailure::InvalidConfiguration("code_release_failed"))
    }
    pub(super) async fn save_code_checkpoint(
        &self,
        run: &ClaimedRun,
        binding: &RepositoryBinding,
    ) -> Result<(), RuntimeFailure> {
        let storage = self
            .code_storage
            .as_ref()
            .ok_or(RuntimeFailure::InvalidConfiguration(
                "code_storage_not_configured",
            ))?;
        let id = Uuid::now_v7();
        let commit = storage
            .checkpoint(scope(run), binding, id)
            .await
            .map_err(|_| RuntimeFailure::InvalidConfiguration("code_checkpoint_failed"))?;
        sqlx::query_scalar::<_, Uuid>("select zeus_private.save_code_checkpoint($1,$2,$3,$4,$5)")
            .bind(run.run_id)
            .bind(&self.node_id)
            .bind(run.fence_token)
            .bind(id)
            .bind(commit)
            .fetch_one(&self.pool)
            .await?;
        Ok(())
    }
}
