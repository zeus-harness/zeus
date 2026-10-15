use super::*;

struct Fixture(PathBuf);
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
async fn fixture() -> (Fixture, CodeStorage, CodeScope, RepositoryBinding) {
    let root = std::env::temp_dir().join(format!("zeus-code-test-{}", Uuid::now_v7()));
    let source = root.join("source");
    tokio::fs::create_dir_all(&source).await.unwrap();
    git(&source, &["init", "--initial-branch=main"], false)
        .await
        .unwrap();
    tokio::fs::write(source.join("README.md"), "original\n")
        .await
        .unwrap();
    git(&source, &["add", "."], false).await.unwrap();
    git(&source, &["commit", "-m", "fixture"], false)
        .await
        .unwrap();
    let commit = git(&source, &["rev-parse", "HEAD"], false)
        .await
        .unwrap()
        .trim()
        .to_owned();
    let storage = CodeStorage::new(&root.join("managed")).await.unwrap();
    let scope = CodeScope {
        organization_id: Uuid::now_v7(),
        workspace_id: Uuid::now_v7(),
        run_id: Uuid::now_v7(),
        fence: 1,
    };
    let binding = RepositoryBinding {
        repository_id: Uuid::now_v7(),
        commit,
    };
    storage
        .import(scope, binding.repository_id, source.to_str().unwrap())
        .await
        .unwrap();
    (Fixture(root), storage, scope, binding)
}

#[tokio::test]
async fn checkpoint_survives_directory_removal_and_runs_are_independent() {
    let (_fixture, storage, scope, binding) = fixture().await;
    let directory = storage.prepare(scope, &binding, None).await.unwrap();
    let second = CodeScope {
        run_id: Uuid::now_v7(),
        ..scope
    };
    let second_directory = storage.prepare(second, &binding, None).await.unwrap();
    tokio::fs::write(directory.join("README.md"), "changed\n")
        .await
        .unwrap();
    tokio::fs::write(directory.join("new.txt"), "untracked\n")
        .await
        .unwrap();
    let checkpoint = storage
        .checkpoint(scope, &binding, Uuid::now_v7())
        .await
        .unwrap();
    storage.release(scope, &binding).await.unwrap();
    assert!(!directory.exists());
    assert_eq!(
        tokio::fs::read_to_string(second_directory.join("README.md"))
            .await
            .unwrap(),
        "original\n"
    );
    let resumed = CodeScope { fence: 2, ..scope };
    let restored = storage
        .prepare(resumed, &binding, Some(&checkpoint))
        .await
        .unwrap();
    assert_eq!(
        tokio::fs::read_to_string(restored.join("README.md"))
            .await
            .unwrap(),
        "changed\n"
    );
    assert_eq!(
        tokio::fs::read_to_string(restored.join("new.txt"))
            .await
            .unwrap(),
        "untracked\n"
    );
    assert_eq!(binding.commit.len(), 40);
    assert!(
        storage.prepare(resumed, &binding, None).await.is_err(),
        "cannot reset live changes"
    );
    let other_tenant = CodeScope {
        organization_id: Uuid::now_v7(),
        ..scope
    };
    assert!(matches!(
        storage.prepare(other_tenant, &binding, None).await,
        Err(CodeError::Unavailable)
    ));
    storage.release(second, &binding).await.unwrap();
    storage.release(resumed, &binding).await.unwrap();
}

#[tokio::test]
async fn checkpoint_rejects_symlinks_and_oversized_files() {
    let (_fixture, storage, scope, binding) = fixture().await;
    let directory = storage.prepare(scope, &binding, None).await.unwrap();
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink("/etc/passwd", directory.join("escape")).unwrap();
        assert!(matches!(
            storage.checkpoint(scope, &binding, Uuid::now_v7()).await,
            Err(CodeError::Invalid)
        ));
        tokio::fs::remove_file(directory.join("escape"))
            .await
            .unwrap();
    }
    let file = tokio::fs::File::create(directory.join("large.bin"))
        .await
        .unwrap();
    file.set_len(MAX_BYTES + 1).await.unwrap();
    assert!(matches!(
        storage.checkpoint(scope, &binding, Uuid::now_v7()).await,
        Err(CodeError::Limit)
    ));
}

#[test]
fn bindings_require_a_full_commit_not_a_branch_or_option() {
    assert!(valid_commit(&"a".repeat(40)));
    for invalid in ["main", "--upload-pack=anything", "../../outside", "abc123"] {
        assert!(!valid_commit(invalid));
    }
}

#[tokio::test]
async fn checkpoint_rejects_git_metadata_redirect() {
    let (_fixture, storage, scope, binding) = fixture().await;
    let directory = storage.prepare(scope, &binding, None).await.unwrap();
    tokio::fs::write(
        directory.join(".git"),
        format!(
            "gitdir: {}",
            storage.repository(scope, binding.repository_id).display()
        ),
    )
    .await
    .unwrap();
    assert!(matches!(
        storage.checkpoint(scope, &binding, Uuid::now_v7()).await,
        Err(CodeError::Invalid)
    ));
}

#[cfg(unix)]
#[tokio::test]
async fn cancellation_guard_terminates_the_process_group() {
    let mut child = Command::new("/bin/sleep")
        .arg("30")
        .process_group(0)
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    drop(GitProcessGroup(child.id()));
    let status = tokio::time::timeout(Duration::from_secs(3), child.wait())
        .await
        .unwrap()
        .unwrap();
    assert!(!status.success());
}
