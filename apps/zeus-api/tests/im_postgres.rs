use sqlx::PgPool;
use uuid::Uuid;
use zeus_api::{
    HTTP_DATABASE_ROLE, connect_pool, connect_pool_as_role,
    database::{TenantScope, begin_tenant},
    migrate,
};

async fn send(
    pool: &PgPool,
    org: Uuid,
    user: Uuid,
    conv: Uuid,
    key: Uuid,
    content: &str,
) -> Result<Uuid, sqlx::Error> {
    let mut tx = begin_tenant(pool, TenantScope::organization(Some(user), org)).await?;
    let id = sqlx::query_scalar("select zeus_private.im_send($1,$2,$3,null,'{}'::uuid[])")
        .bind(conv)
        .bind(key)
        .bind(content)
        .fetch_one(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(id)
}
async fn visible(pool: &PgPool, org: Uuid, user: Uuid, conv: Uuid) -> i64 {
    let mut tx = begin_tenant(pool, TenantScope::organization(Some(user), org))
        .await
        .unwrap();
    sqlx::query_scalar("select count(*) from im_messages where conversation_id=$1")
        .bind(conv)
        .fetch_one(&mut *tx)
        .await
        .unwrap()
}
#[tokio::test]
#[ignore = "requires ZEUS_TEST_DATABASE_URL"]
#[allow(clippy::too_many_lines)]
async fn organization_im_enforces_membership_concurrency_and_history_boundaries() {
    let url = std::env::var("ZEUS_TEST_DATABASE_URL").unwrap();
    let owner = connect_pool(&url, 5).await.unwrap();
    migrate(&owner).await.unwrap();
    let http = connect_pool_as_role(&url, 5, HTTP_DATABASE_ROLE)
        .await
        .unwrap();
    let org = Uuid::now_v7();
    let outside_org = Uuid::now_v7();
    let alice = Uuid::now_v7();
    let bob = Uuid::now_v7();
    let carol = Uuid::now_v7();
    let outsider = Uuid::now_v7();
    for organization in [org, outside_org] {
        sqlx::query("insert into organizations(id,slug,name,status) values($1,$2,'IM fixture','provisioning')").bind(organization).bind(organization.to_string()).execute(&owner).await.unwrap();
    }
    for (user, organization, name) in [
        (alice, org, "Alice"),
        (bob, org, "Bob"),
        (carol, org, "Carol"),
        (outsider, outside_org, "Outsider"),
    ] {
        sqlx::query("insert into users(id,email,display_name,status,email_verified_at) values($1,$2,$3,'active',now())").bind(user).bind(format!("{user}@im.invalid")).bind(name).execute(&owner).await.unwrap();
        sqlx::query("insert into organization_memberships(organization_id,user_id,role,status) values($1,$2,'owner','active')").bind(organization).bind(user).execute(&owner).await.unwrap();
    }
    sqlx::query("update organizations set status='active' where id=any($1)")
        .bind(vec![org, outside_org])
        .execute(&owner)
        .await
        .unwrap();
    let mut tx = begin_tenant(&http, TenantScope::organization(Some(alice), org))
        .await
        .unwrap();
    let group: Uuid =
        sqlx::query_scalar("select zeus_private.im_create($1,'group','Test group',$2,$3)")
            .bind(org)
            .bind(vec![bob])
            .bind(Uuid::now_v7())
            .fetch_one(&mut *tx)
            .await
            .unwrap();
    tx.commit().await.unwrap();
    let key = Uuid::now_v7();
    let (first, retry) = tokio::join!(
        send(&http, org, alice, group, key, "one"),
        send(&http, org, alice, group, key, "one")
    );
    let first = first.unwrap();
    assert_eq!(first, retry.unwrap());
    assert_eq!(visible(&http, org, bob, group).await, 1);
    assert_eq!(
        visible(&http, org, carol, group).await,
        0,
        "organization owner cannot read another chat"
    );
    assert_eq!(visible(&http, outside_org, outsider, group).await, 0);
    assert!(
        send(&http, org, carol, group, Uuid::now_v7(), "unauthorized")
            .await
            .is_err()
    );
    assert!(
        send(&http, org, alice, group, key, "changed")
            .await
            .is_err()
    );
    let (a, b) = tokio::join!(
        send(&http, org, alice, group, Uuid::now_v7(), "two"),
        send(&http, org, bob, group, Uuid::now_v7(), "three")
    );
    a.unwrap();
    b.unwrap();
    let sequences: Vec<i64> = sqlx::query_scalar(
        "select sequence from im_messages where conversation_id=$1 order by sequence",
    )
    .bind(group)
    .fetch_all(&owner)
    .await
    .unwrap();
    assert_eq!(sequences, vec![1, 2, 3]);
    let mut tx = begin_tenant(&http, TenantScope::organization(Some(alice), org))
        .await
        .unwrap();
    sqlx::query("select zeus_private.im_change($1,'add','',$2)")
        .bind(group)
        .bind(carol)
        .execute(&mut *tx)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    assert_eq!(
        visible(&http, org, carol, group).await,
        0,
        "new participant starts after existing history"
    );
    send(
        &http,
        org,
        bob,
        group,
        Uuid::now_v7(),
        "new member can see this",
    )
    .await
    .unwrap();
    assert_eq!(visible(&http, org, carol, group).await, 1);
    let mut tx = begin_tenant(&http, TenantScope::organization(Some(carol), org))
        .await
        .unwrap();
    assert!(
        sqlx::query("select zeus_private.im_send($1,$2,'hidden reply',$3,'{}'::uuid[])")
            .bind(group)
            .bind(Uuid::now_v7())
            .bind(first)
            .execute(&mut *tx)
            .await
            .is_err()
    );
    tx.rollback().await.unwrap();
    let mut tx = begin_tenant(&http, TenantScope::organization(Some(bob), org))
        .await
        .unwrap();
    sqlx::query("select zeus_private.im_change($1,'read','4',null)")
        .bind(group)
        .execute(&mut *tx)
        .await
        .unwrap();
    let read: i64 = sqlx::query_scalar(
        "select last_read_sequence from im_members where conversation_id=$1 and user_id=$2",
    )
    .bind(group)
    .bind(bob)
    .fetch_one(&mut *tx)
    .await
    .unwrap();
    assert_eq!(read, 4);
    sqlx::query("select zeus_private.im_change($1,'leave','',null)")
        .bind(group)
        .execute(&mut *tx)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    assert_eq!(visible(&http, org, bob, group).await, 0);
    assert!(
        send(&http, org, bob, group, Uuid::now_v7(), "left")
            .await
            .is_err()
    );
    let mut tx = begin_tenant(&http, TenantScope::organization(Some(alice), org))
        .await
        .unwrap();
    assert!(
        sqlx::query("select zeus_private.im_change($1,'add','',$2)")
            .bind(group)
            .bind(outsider)
            .execute(&mut *tx)
            .await
            .is_err()
    );
    tx.rollback().await.unwrap();
    let mut tx = begin_tenant(&http, TenantScope::organization(Some(alice), org))
        .await
        .unwrap();
    let direct: Uuid =
        sqlx::query_scalar("select zeus_private.im_create($1,'direct','Direct',$2,$3)")
            .bind(org)
            .bind(vec![carol])
            .bind(Uuid::now_v7())
            .fetch_one(&mut *tx)
            .await
            .unwrap();
    tx.commit().await.unwrap();
    let mut tx = begin_tenant(&http, TenantScope::organization(Some(carol), org))
        .await
        .unwrap();
    let same: Uuid =
        sqlx::query_scalar("select zeus_private.im_create($1,'direct','Direct',$2,$3)")
            .bind(org)
            .bind(vec![alice])
            .bind(Uuid::now_v7())
            .fetch_one(&mut *tx)
            .await
            .unwrap();
    assert_eq!(direct, same);
    tx.commit().await.unwrap();
    let mut tx = begin_tenant(
        &http,
        TenantScope {
            user_id: Some(alice),
            organization_id: org,
            workspace_id: None,
            session_id: None,
            tenant_access_grant_id: Some(Uuid::now_v7()),
        },
    )
    .await
    .unwrap();
    let count: i64 = sqlx::query_scalar("select count(*) from im_messages")
        .fetch_one(&mut *tx)
        .await
        .unwrap();
    assert_eq!(count, 0, "support mode has no access to chat");
    tx.rollback().await.unwrap();
    verify_agent_boundaries(&owner, &http, org, alice, carol, group).await;
    sqlx::query("update organization_memberships set status='suspended' where organization_id=$1 and user_id=$2").bind(org).bind(carol).execute(&owner).await.unwrap();
    assert_eq!(visible(&http, org, carol, group).await, 0);
}

#[allow(clippy::too_many_lines)]
async fn verify_agent_boundaries(
    pool: &PgPool,
    http: &PgPool,
    org: Uuid,
    alice: Uuid,
    carol: Uuid,
    group: Uuid,
) {
    let workspace = Uuid::now_v7();
    let connection = Uuid::now_v7();
    let model = Uuid::now_v7();
    let agent = Uuid::now_v7();
    let av = Uuid::now_v7();
    let workflow = Uuid::now_v7();
    let version = Uuid::now_v7();
    let late = Uuid::now_v7();
    // Generated UUIDs only; this fixture intentionally has no provider credential or running API.
    sqlx::raw_sql(&format!(r"
      insert into workspaces(id,organization_id,slug,name) values('{workspace}','{org}','{workspace}','Chat');
      insert into workspace_memberships(organization_id,workspace_id,user_id,role,status) values('{org}','{workspace}','{alice}','owner','active');
      insert into connections(id,organization_id,name,provider_kind) values('{connection}','{org}','Chat model','openai_compatible');
      insert into model_profiles(id,organization_id,connection_id,name,base_url,model) values('{model}','{org}','{connection}','Chat model','https://example.invalid/v1','fixture');
      insert into agents(id,organization_id,workspace_id,name) values('{agent}','{org}','{workspace}','Assistant');
      insert into agent_versions(id,organization_id,workspace_id,agent_id,version_number,instructions) values('{av}','{org}','{workspace}','{agent}',1,'Reply');
      insert into workflows(id,organization_id,workspace_id,name) values('{workflow}','{org}','{workspace}','Chat');
      insert into workflow_versions(id,organization_id,workspace_id,workflow_id,version_number,agent_version_id,model_profile_id,input_schema,output_schema) values('{version}','{org}','{workspace}','{workflow}',1,'{av}','{model}','{{}}','{{}}');
      update workflows set active_version_id='{version}' where id='{workflow}';
      insert into users(id,email,display_name,status,email_verified_at) values('{late}','{late}@im.invalid','Late','active',now());
      insert into organization_memberships(organization_id,user_id,role,status) values('{org}','{late}','member','active');
    ")).execute(pool).await.unwrap();
    let scope = TenantScope {
        user_id: Some(alice),
        organization_id: org,
        workspace_id: Some(workspace),
        session_id: None,
        tenant_access_grant_id: None,
    };
    let mut tx = begin_tenant(http, scope).await.unwrap();
    let member: Uuid = sqlx::query_scalar("select zeus_private.im_add_agent($1,$2)")
        .bind(group)
        .bind(version)
        .fetch_one(&mut *tx)
        .await
        .unwrap();
    let same: Uuid = sqlx::query_scalar("select zeus_private.im_add_agent($1,$2)")
        .bind(group)
        .bind(version)
        .fetch_one(&mut *tx)
        .await
        .unwrap();
    assert_eq!(
        member, same,
        "adding the same published version is idempotent"
    );
    tx.commit().await.unwrap();
    let source = send(
        http,
        org,
        alice,
        group,
        Uuid::now_v7(),
        "Please summarize this request",
    )
    .await
    .unwrap();
    let session = Uuid::now_v7();
    let run = Uuid::now_v7();
    sqlx::query("insert into sessions(id,organization_id,workspace_id,title,created_by) values($1,$2,$3,'Invocation',$4)").bind(session).bind(org).bind(workspace).bind(alice).execute(pool).await.unwrap();
    sqlx::query("insert into runs(id,organization_id,workspace_id,workflow_version_id,session_id,idempotency_key,created_by) values($1,$2,$3,$4,$5,$1::text,$6)").bind(run).bind(org).bind(workspace).bind(version).bind(session).bind(alice).execute(pool).await.unwrap();
    let mut tx = begin_tenant(
        http,
        TenantScope {
            user_id: Some(carol),
            ..scope
        },
    )
    .await
    .unwrap();
    assert!(
        sqlx::query("select zeus_private.im_link_agent_run($1,$2,$3)")
            .bind(member)
            .bind(source)
            .bind(run)
            .execute(&mut *tx)
            .await
            .is_err(),
        "organization member has no workspace execution permission"
    );
    tx.rollback().await.unwrap();
    let mut tx = begin_tenant(http, scope).await.unwrap();
    let old: Uuid = sqlx::query_scalar(
        "select id from im_messages where conversation_id=$1 order by sequence limit 1",
    )
    .bind(group)
    .fetch_one(&mut *tx)
    .await
    .unwrap();
    assert!(
        sqlx::query("select zeus_private.im_link_agent_run($1,$2,$3)")
            .bind(member)
            .bind(old)
            .bind(run)
            .execute(&mut *tx)
            .await
            .is_err(),
        "Agent cannot access pre-join history"
    );
    tx.rollback().await.unwrap();
    let mut tx = begin_tenant(http, scope).await.unwrap();
    sqlx::query("select zeus_private.im_link_agent_run($1,$2,$3)")
        .bind(member)
        .bind(source)
        .bind(run)
        .execute(&mut *tx)
        .await
        .unwrap();
    sqlx::query("select zeus_private.im_change($1,'add','',$2)")
        .bind(group)
        .bind(late)
        .execute(&mut *tx)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    // Simulate a committed terminal transition; provider quality is tested separately.
    sqlx::query(
        "update runs set status='succeeded',output='{\"content\":\"Group reply\"}' where id=$1",
    )
    .bind(run)
    .execute(pool)
    .await
    .unwrap();
    sqlx::query("update runs set status='succeeded' where id=$1")
        .bind(run)
        .execute(pool)
        .await
        .unwrap();
    let count: i64 = sqlx::query_scalar("select count(*) from im_messages where agent_run_id=$1")
        .bind(run)
        .fetch_one(pool)
        .await
        .unwrap();
    assert_eq!(count, 1, "terminal reply is durable and not duplicated");
    let mut tx = begin_tenant(http, TenantScope::organization(Some(carol), org))
        .await
        .unwrap();
    let reply: String = sqlx::query_scalar("select content from im_messages where agent_run_id=$1")
        .bind(run)
        .fetch_one(&mut *tx)
        .await
        .unwrap();
    assert_eq!(
        reply, "Group reply",
        "conversation member can read shared reply without workspace membership"
    );
    tx.rollback().await.unwrap();
    assert_eq!(
        visible(http, org, late, group).await,
        0,
        "joining while a Run is pending does not reveal an older private request via its result"
    );
    let mut tx = begin_tenant(http, TenantScope::organization(Some(late), org))
        .await
        .unwrap();
    let calls: i64 = sqlx::query_scalar("select count(*) from zeus_private.im_agent_calls($1)")
        .bind(group)
        .fetch_one(&mut *tx)
        .await
        .unwrap();
    assert_eq!(calls, 0, "late joiner cannot read earlier execution links");
    tx.rollback().await.unwrap();
    let mut tx = begin_tenant(http, TenantScope::organization(Some(carol), org))
        .await
        .unwrap();
    assert!(
        sqlx::query("select zeus_private.im_remove_agent($1,$2)")
            .bind(group)
            .bind(member)
            .execute(&mut *tx)
            .await
            .is_err(),
        "only conversation owner manages Agent membership"
    );
    tx.rollback().await.unwrap();
    let second_source = send(http, org, alice, group, Uuid::now_v7(), "Second request")
        .await
        .unwrap();
    let second_run = Uuid::now_v7();
    sqlx::query("insert into runs(id,organization_id,workspace_id,workflow_version_id,session_id,idempotency_key,created_by) values($1,$2,$3,$4,$5,$1::text,$6)")
        .bind(second_run).bind(org).bind(workspace).bind(version).bind(session).bind(alice).execute(pool).await.unwrap();
    let mut tx = begin_tenant(http, scope).await.unwrap();
    sqlx::query("select zeus_private.im_link_agent_run($1,$2,$3)")
        .bind(member)
        .bind(second_source)
        .bind(second_run)
        .execute(&mut *tx)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    let mut tx = begin_tenant(http, scope).await.unwrap();
    sqlx::query("select zeus_private.im_remove_agent($1,$2)")
        .bind(group)
        .bind(member)
        .execute(&mut *tx)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    let mut tx = begin_tenant(http, scope).await.unwrap();
    assert!(
        sqlx::query("select zeus_private.im_link_agent_run($1,$2,$3)")
            .bind(member)
            .bind(source)
            .bind(run)
            .execute(&mut *tx)
            .await
            .is_err(),
        "removed Agent cannot be invoked"
    );
    tx.rollback().await.unwrap();
    sqlx::query(
        "update runs set status='succeeded',output='{\"content\":\"Do not deliver\"}' where id=$1",
    )
    .bind(second_run)
    .execute(pool)
    .await
    .unwrap();
    let delivered: i64 =
        sqlx::query_scalar("select count(*) from im_messages where agent_run_id=$1")
            .bind(second_run)
            .fetch_one(pool)
            .await
            .unwrap();
    assert_eq!(
        delivered, 0,
        "removal while pending prevents later result delivery"
    );
}
