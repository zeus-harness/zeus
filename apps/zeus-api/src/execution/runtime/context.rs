use secrecy::SecretString;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use super::{
    DurableRunExecutor,
    events::{StoredSessionEvent, append_run_event_in_transaction},
    types::{InjectedExperience, RunPlan, RuntimeFailure, SecretRow},
};
use crate::{crypto::SealedSecret, supervisor::ClaimedRun};

impl DurableRunExecutor {
    pub(super) async fn load_plan(&self, run: &ClaimedRun) -> Result<RunPlan, RuntimeFailure> {
        sqlx::query_as::<_, RunPlan>(
            "select av.instructions,
                    mp.id as model_profile_id,
                    mp.revision as model_profile_revision,
                    mp.connection_id as model_connection_id,
                    c.configuration as model_connection_configuration,
                    mp.base_url as model_base_url,
                    mp.model,
                    mp.configuration as model_configuration,
                    wv.capability_policy,
                    wv.approval_policy,
                    wv.experience_policy,
                    wv.max_steps,
                    coalesce(current_run.max_runtime_seconds_override, wv.max_runtime_seconds)
                      as max_runtime_seconds,
                    coalesce(current_run.token_budget_override, wv.token_budget) as token_budget,
                    wv.retry_policy,
                    coalesce(current_run.started_at, now()) as started_at
             from workflow_versions wv
             join runs current_run on current_run.id = $4
             join agent_versions av on av.id = wv.agent_version_id
             join model_profiles mp on mp.id = wv.model_profile_id
             join connections c on c.id = mp.connection_id
             where wv.id = $1
               and wv.organization_id = $2 and wv.workspace_id = $3
               and av.organization_id = $2 and av.workspace_id = $3
               and mp.organization_id = $2 and mp.workspace_id = $3
               and c.organization_id = $2 and c.workspace_id = $3
               and current_run.organization_id = $2 and current_run.workspace_id = $3
               and mp.archived_at is null and c.archived_at is null",
        )
        .bind(run.workflow_version_id)
        .bind(run.organization_id)
        .bind(run.workspace_id)
        .bind(run.run_id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or(RuntimeFailure::InvalidConfiguration(
            "runtime_configuration_unavailable",
        ))
    }

    pub(super) async fn load_model_api_key(
        &self,
        run: &ClaimedRun,
        plan: &RunPlan,
    ) -> Result<SecretString, RuntimeFailure> {
        let secret_name = plan
            .model_connection_configuration
            .get("api_key_secret_name")
            .and_then(Value::as_str)
            .unwrap_or("api_key");
        if secret_name.is_empty() || secret_name.len() > 128 {
            return Err(RuntimeFailure::InvalidConfiguration(
                "invalid_model_secret_name",
            ));
        }
        let row = sqlx::query_as::<_, SecretRow>(
            "select secret_name, ciphertext, nonce, key_id
             from connection_secrets
             where organization_id = $1 and workspace_id = $2
               and connection_id = $3 and secret_name = $4",
        )
        .bind(run.organization_id)
        .bind(run.workspace_id)
        .bind(plan.model_connection_id)
        .bind(secret_name)
        .fetch_optional(&self.pool)
        .await?
        .ok_or(RuntimeFailure::InvalidConfiguration(
            "model_credential_unavailable",
        ))?;
        let aad = format!(
            "connection/{}/{}",
            plan.model_connection_id, row.secret_name
        );
        let plaintext = self
            .envelope
            .open(
                &SealedSecret {
                    ciphertext: row.ciphertext,
                    nonce: row.nonce,
                    key_id: row.key_id,
                },
                aad.as_bytes(),
            )
            .map_err(|_| RuntimeFailure::InvalidConfiguration("model_credential_unavailable"))?;
        let plaintext = String::from_utf8(plaintext)
            .map_err(|_| RuntimeFailure::InvalidConfiguration("model_credential_unavailable"))?;
        Ok(SecretString::from(plaintext))
    }

    pub(super) async fn load_session_events(
        &self,
        run: &ClaimedRun,
    ) -> Result<Vec<zeus_core::SessionEvent>, RuntimeFailure> {
        let rows = sqlx::query_as::<_, StoredSessionEvent>(
            "select id, session_id, run_id, sequence, schema_version,
                    event_type, actor_kind, actor_id, payload, occurred_at
             from session_events
             where organization_id = $1 and workspace_id = $2 and session_id = $3
             order by sequence",
        )
        .bind(run.organization_id)
        .bind(run.workspace_id)
        .bind(run.session_id)
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter()
            .filter_map(StoredSessionEvent::into_domain)
            .collect::<Result<Vec<_>, _>>()
    }

    pub(super) async fn load_experience_context(
        &self,
        run: &ClaimedRun,
        plan: &RunPlan,
    ) -> Result<Vec<InjectedExperience>, RuntimeFailure> {
        let existing = self.load_recorded_experiences(run).await?;
        if !existing.is_empty() || self.experience_selection_completed(run).await? {
            return Ok(existing);
        }

        let limit = plan.experience_limit();
        let include_workspace = plan.include_workspace_experience();
        let include_organization = plan.include_organization_experience();
        let query = self.latest_experience_query(run).await?;
        let mut selected =
            if limit == 0 || (!include_workspace && !include_organization) || query.is_empty() {
                Vec::new()
            } else {
                sqlx::query_as::<_, InjectedExperience>(
                    "with query as (select plainto_tsquery('simple', $3) as value)
                 select e.id, e.scope, e.version_number, e.title, e.content,
                        greatest(ts_rank(e.search_vector, query.value), 0)::real as rank
                 from experience_entries e
                 cross join query
                 left join experience_entry_withdrawals w on w.experience_entry_id = e.id
                 where e.organization_id = $1
                   and (
                     ($4 and e.scope = 'workspace' and e.workspace_id = $2)
                     or ($5 and e.scope = 'organization' and e.workspace_id is null)
                   )
                   and w.experience_entry_id is null
                   and e.search_vector @@ query.value
                 order by rank desc, e.published_at desc, e.id desc
                 limit $6",
                )
                .bind(run.organization_id)
                .bind(run.workspace_id)
                .bind(&query)
                .bind(include_workspace)
                .bind(include_organization)
                .bind(i64::from(limit))
                .fetch_all(&self.pool)
                .await?
            };

        let query_sha256 = Sha256::digest(query.as_bytes()).to_vec();
        let mut transaction = self.begin_fenced(run).await?;
        for item in &selected {
            sqlx::query(
                "insert into run_experience_injections (
                    organization_id, workspace_id, run_id, experience_entry_id,
                    experience_version, rank, query_sha256
                 ) values ($1, $2, $3, $4, $5, $6, $7)
                 on conflict (run_id, experience_entry_id) do nothing",
            )
            .bind(run.organization_id)
            .bind(run.workspace_id)
            .bind(run.run_id)
            .bind(item.id)
            .bind(item.version_number)
            .bind(item.rank)
            .bind(&query_sha256)
            .execute(&mut *transaction)
            .await?;
        }
        append_run_event_in_transaction(
            &mut transaction,
            run,
            "experience.selection_completed",
            json!({
                "entries": selected.iter().map(|item| json!({
                    "experience_entry_id": item.id,
                    "version": item.version_number,
                    "scope": item.scope,
                    "rank": item.rank,
                })).collect::<Vec<_>>(),
                "query_sha256": hex::encode(&query_sha256),
            }),
            None,
        )
        .await?;
        transaction.commit().await?;

        selected.truncate(usize::from(limit));
        Ok(selected)
    }

    async fn load_recorded_experiences(
        &self,
        run: &ClaimedRun,
    ) -> Result<Vec<InjectedExperience>, RuntimeFailure> {
        sqlx::query_as::<_, InjectedExperience>(
            "select e.id, e.scope, i.experience_version as version_number,
                    e.title, e.content, i.rank
             from run_experience_injections i
             join experience_entries e on e.id = i.experience_entry_id
             where i.organization_id = $1 and i.workspace_id = $2 and i.run_id = $3
               and e.organization_id = $1
             order by i.rank desc, i.injected_at, i.id",
        )
        .bind(run.organization_id)
        .bind(run.workspace_id)
        .bind(run.run_id)
        .fetch_all(&self.pool)
        .await
        .map_err(Into::into)
    }

    async fn experience_selection_completed(
        &self,
        run: &ClaimedRun,
    ) -> Result<bool, RuntimeFailure> {
        sqlx::query_scalar(
            "select exists(
               select 1 from run_events
               where organization_id = $1 and workspace_id = $2 and run_id = $3
                 and event_type = 'experience.selection_completed'
             )",
        )
        .bind(run.organization_id)
        .bind(run.workspace_id)
        .bind(run.run_id)
        .fetch_one(&self.pool)
        .await
        .map_err(Into::into)
    }

    async fn latest_experience_query(&self, run: &ClaimedRun) -> Result<String, RuntimeFailure> {
        let content = sqlx::query_scalar::<_, String>(
            "select payload ->> 'content'
             from session_events
             where organization_id = $1 and workspace_id = $2 and session_id = $3
               and event_type in ('user_message', 'steering_message')
               and jsonb_typeof(payload -> 'content') = 'string'
             order by sequence desc limit 1",
        )
        .bind(run.organization_id)
        .bind(run.workspace_id)
        .bind(run.session_id)
        .fetch_optional(&self.pool)
        .await?
        .unwrap_or_default();
        Ok(content.trim().chars().take(2_000).collect())
    }

    pub(super) async fn used_tokens(&self, run: &ClaimedRun) -> Result<u64, RuntimeFailure> {
        let used: i64 = sqlx::query_scalar(
            "select coalesce(sum(prompt_tokens + completion_tokens), 0)::bigint
             from run_usage
             where organization_id = $1 and workspace_id = $2 and run_id = $3",
        )
        .bind(run.organization_id)
        .bind(run.workspace_id)
        .bind(run.run_id)
        .fetch_one(&self.pool)
        .await?;
        u64::try_from(used).map_err(|_| RuntimeFailure::Database)
    }
}
