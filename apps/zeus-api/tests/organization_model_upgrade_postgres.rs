use std::borrow::Cow;

use sqlx::migrate::Migrator;
use uuid::Uuid;
use zeus_api::{connect_pool, migrate};

#[tokio::test]
#[ignore = "requires a fresh ZEUS_TEST_DATABASE_URL; use pnpm test:postgres"]
async fn organization_models_preserve_existing_ids_secrets_and_distinct_names() {
    let url = std::env::var("ZEUS_TEST_DATABASE_URL").expect("test database is configured");
    let pool = connect_pool(&url, 2).await.expect("connect");
    let migrations = sqlx::migrate!("../../db/migrations");
    let baseline = Migrator {
        migrations: Cow::Owned(
            migrations
                .iter()
                .filter(|migration| migration.version <= 30)
                .cloned()
                .collect(),
        ),
        ..Migrator::DEFAULT
    };
    baseline.run(&pool).await.expect("migrate to 30");
    let organization_id = Uuid::now_v7();
    sqlx::query("insert into organizations (id, slug, name, status) values ($1, $2, 'Model upgrade', 'provisioning')")
        .bind(organization_id)
        .bind(organization_id.to_string())
        .execute(&pool)
        .await
        .expect("organization");
    let mut ids = Vec::new();
    for _ in 0..2 {
        let workspace_id = Uuid::now_v7();
        let connection_id = Uuid::now_v7();
        let model_id = Uuid::now_v7();
        sqlx::query("insert into workspaces (id, organization_id, slug, name) values ($1, $2, $3, 'Legacy workspace')")
            .bind(workspace_id).bind(organization_id).bind(workspace_id.to_string()).execute(&pool).await.expect("workspace");
        sqlx::query("insert into connections (id, organization_id, workspace_id, name, provider_kind) values ($1, $2, $3, 'Same provider name', 'openai_compatible')")
            .bind(connection_id).bind(organization_id).bind(workspace_id).execute(&pool).await.expect("provider");
        sqlx::query("insert into connection_secrets (organization_id, workspace_id, connection_id, secret_name, ciphertext, nonce, key_id) values ($1, $2, $3, 'api_key', $4, $5, 'synthetic-key-id')")
            .bind(organization_id).bind(workspace_id).bind(connection_id).bind(vec![42_u8; 32]).bind(vec![0_u8; 12]).execute(&pool).await.expect("synthetic ciphertext");
        sqlx::query("insert into model_profiles (id, organization_id, workspace_id, connection_id, name, base_url, model) values ($1, $2, $3, $4, 'Same model name', 'https://model.example.test', 'synthetic')")
            .bind(model_id).bind(organization_id).bind(workspace_id).bind(connection_id).execute(&pool).await.expect("model");
        ids.push((connection_id, model_id));
    }
    migrate(&pool).await.expect("organization model upgrade");
    for (connection_id, model_id) in ids {
        let row: (Option<Uuid>, Vec<u8>) = sqlx::query_as(
            "select workspace_id, ciphertext from connection_secrets where connection_id = $1",
        )
        .bind(connection_id)
        .fetch_one(&pool)
        .await
        .expect("secret preserved");
        assert!(row.0.is_none());
        assert_eq!(row.1, vec![42_u8; 32]);
        let row: (Option<Uuid>, Uuid) =
            sqlx::query_as("select workspace_id, connection_id from model_profiles where id = $1")
                .bind(model_id)
                .fetch_one(&pool)
                .await
                .expect("model preserved");
        assert_eq!(row, (None, connection_id));
    }
    let names: i64 = sqlx::query_scalar(
        "select count(distinct name) from model_profiles where organization_id = $1",
    )
    .bind(organization_id)
    .fetch_one(&pool)
    .await
    .expect("names");
    assert_eq!(names, 2);
}
