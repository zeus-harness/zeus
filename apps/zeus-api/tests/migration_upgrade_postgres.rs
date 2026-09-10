use std::borrow::Cow;

use sqlx::migrate::Migrator;
use uuid::Uuid;
use zeus_api::{connect_pool, migrate};

#[tokio::test]
#[ignore = "requires a fresh ZEUS_TEST_DATABASE_URL; use pnpm test:postgres"]
async fn platform_owner_upgrade_preserves_existing_assignments_and_permissions() {
    let database_url = std::env::var("ZEUS_TEST_DATABASE_URL")
        .expect("ZEUS_TEST_DATABASE_URL is required for this ignored test");
    let pool = connect_pool(&database_url, 2)
        .await
        .expect("test database connects");
    let initialized: bool = sqlx::query_scalar("select to_regclass('public.users') is not null")
        .fetch_one(&pool)
        .await
        .expect("database state loads");
    assert!(
        !initialized,
        "upgrade test requires a fresh temporary database"
    );

    let migrations = sqlx::migrate!("../../db/migrations");
    let before_cutover = Migrator {
        migrations: Cow::Owned(
            migrations
                .iter()
                .filter(|migration| migration.version <= 29)
                .cloned()
                .collect(),
        ),
        ..Migrator::DEFAULT
    };
    before_cutover
        .run(&pool)
        .await
        .expect("database migrates to version 29");

    let user_id = Uuid::now_v7();
    sqlx::query(
        "insert into users (id, email, display_name, status, email_verified_at)
         values ($1, $2, 'Upgrade Owner', 'active', now())",
    )
    .bind(user_id)
    .bind(format!("upgrade-{user_id}@example.test"))
    .execute(&pool)
    .await
    .expect("existing user inserts");
    sqlx::query(
        "insert into platform_role_assignments (user_id, role, assigned_by)
         values ($1, 'platform_admin', $1)",
    )
    .bind(user_id)
    .execute(&pool)
    .await
    .expect("pre-cutover role inserts");

    migrate(&pool).await.expect("populated database upgrades");
    migrate(&pool).await.expect("repeated migration is a no-op");
    let assignment: (String, Uuid, bool) = sqlx::query_as(
        "select role, assigned_by, revoked_at is null
         from platform_role_assignments where user_id = $1",
    )
    .bind(user_id)
    .fetch_one(&pool)
    .await
    .expect("existing role survives");
    assert_eq!(assignment, ("platform_owner".to_owned(), user_id, true));

    let contract: (bool, bool, bool, bool, bool) = sqlx::query_as(
        "select zeus_private.has_platform_owner(),
           to_regprocedure('zeus_private.has_platform_admin()') is null,
           to_regprocedure('zeus_private.platform_session_is_admin(uuid,uuid,boolean)') is null,
           has_function_privilege('zeus_http', 'zeus_private.has_platform_owner()', 'EXECUTE'),
           not exists (
             select 1 from pg_proc p join pg_namespace n on n.oid = p.pronamespace
             where n.nspname = 'zeus_private' and position('platform_admin' in p.prosrc) > 0
           )",
    )
    .fetch_one(&pool)
    .await
    .expect("upgraded functions retain their contract");
    assert_eq!(contract, (true, true, true, true, true));
    pool.close().await;
}
