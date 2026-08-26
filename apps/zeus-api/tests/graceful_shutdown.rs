#![cfg(unix)]

use std::{
    fs,
    io::{Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    path::{Path, PathBuf},
    process::{Child, Command, ExitStatus, Stdio},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use runtime::{BootstrapOwnerCommit, DemoStore};
use tenancy::{BootstrapToken, CsrfToken, Password, SessionToken, UserId, Username, hash_password};

const STARTUP_TIMEOUT: Duration = Duration::from_secs(10);
const PROCESS_EXIT_TIMEOUT: Duration = Duration::from_secs(8);

#[test]
fn sigterm_with_active_sse_is_bounded_and_releases_the_database() {
    let fixture_root = unique_fixture_root();
    fs::create_dir_all(&fixture_root).unwrap();
    let database = fixture_root.join("zeus.db");
    let address = unused_local_address();
    let session_token = seed_authenticated_owner(&database);
    let mut child = ChildGuard::spawn(&database, address);

    let _session_sse = open_sse(
        &mut child.child,
        address,
        "/api/v1/sessions/session-ZR-1842/events?after=2",
        session_token.expose_secret(),
    );
    let _run_sse = open_sse(
        &mut child.child,
        address,
        "/api/v1/runs/ZR-1842/events?after=8",
        session_token.expose_secret(),
    );

    let shutdown_started = Instant::now();
    send_sigterm(child.child.id());
    let status = wait_for_exit(&mut child.child, PROCESS_EXIT_TIMEOUT);
    assert!(status.success(), "zeus-api exited with {status}");
    assert!(
        shutdown_started.elapsed() < PROCESS_EXIT_TIMEOUT,
        "bounded shutdown exceeded {PROCESS_EXIT_TIMEOUT:?}"
    );

    // The original database is preserved. Reopening it proves that every
    // Router/DemoStore clone held by the streaming connections was dropped and
    // the process-level SQLite ownership lock was released.
    assert!(database.exists());
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    let reopened = runtime
        .block_on(DemoStore::open(&database))
        .unwrap_or_else(|error| {
            panic!(
                "database {} could not be reopened after shutdown: {error}",
                database.display()
            )
        });
    runtime.block_on(reopened.readiness()).unwrap();
    drop(reopened);
}

fn seed_authenticated_owner(database: &Path) -> SessionToken {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let store = DemoStore::open(database).await.unwrap();
        let bootstrap_token = BootstrapToken::generate().unwrap();
        let session_token = SessionToken::generate().unwrap();
        let csrf_token = CsrfToken::generate().unwrap();
        let user_id = UserId::generate().unwrap();
        let username = Username::parse("shutdown-owner").unwrap();
        let password = Password::new("shutdown test owner password").unwrap();
        let password_hash = hash_password(&password).unwrap();
        let expires_at = (chrono::Utc::now() + chrono::Duration::hours(1))
            .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);

        store
            .replace_bootstrap_token(&bootstrap_token.digest().to_persistence(), &expires_at)
            .await
            .unwrap();
        store
            .bootstrap_owner(BootstrapOwnerCommit {
                bootstrap_token_hash: bootstrap_token.digest().to_persistence(),
                user_id: user_id.to_string(),
                username: username.to_string(),
                password_hash: password_hash.as_phc().to_owned(),
                session_token_hash: session_token.digest().to_persistence(),
                csrf_hash: csrf_token.digest().to_persistence(),
                session_expires_at: expires_at,
            })
            .await
            .unwrap();

        // Release the process-wide database lease before the child starts.
        drop(store);
        session_token
    })
}

fn open_sse(child: &mut Child, address: SocketAddr, path: &str, session_token: &str) -> TcpStream {
    let deadline = Instant::now() + STARTUP_TIMEOUT;
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            panic!("zeus-api exited before SSE connected: {status}");
        }

        if let Ok(mut stream) = TcpStream::connect_timeout(&address, Duration::from_millis(200)) {
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            stream
                .set_write_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let request = format!(
                "GET {path} HTTP/1.1\r\nHost: {address}\r\nAccept: text/event-stream\r\nCookie: zeus_session={session_token}\r\nConnection: keep-alive\r\n\r\n"
            );
            if stream.write_all(request.as_bytes()).is_ok() {
                let mut response = Vec::new();
                let mut chunk = [0_u8; 1024];
                while response.len() < 16 * 1024 {
                    match stream.read(&mut chunk) {
                        Ok(0) => break,
                        Ok(read) => {
                            response.extend_from_slice(&chunk[..read]);
                            if response.windows(4).any(|window| window == b"\r\n\r\n") {
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }
                let response = String::from_utf8_lossy(&response);
                if response.starts_with("HTTP/1.1 200")
                    && response
                        .to_ascii_lowercase()
                        .contains("content-type: text/event-stream")
                {
                    return stream;
                }
            }
        }

        assert!(
            Instant::now() < deadline,
            "zeus-api did not expose SSE at {address} within {STARTUP_TIMEOUT:?}"
        );
        thread::sleep(Duration::from_millis(25));
    }
}

fn send_sigterm(pid: u32) {
    let status = Command::new("kill")
        .arg("-TERM")
        .arg(pid.to_string())
        .status()
        .expect("failed to invoke kill for SIGTERM");
    assert!(status.success(), "kill -TERM failed with {status}");
}

fn wait_for_exit(child: &mut Child, timeout: Duration) -> ExitStatus {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            return status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("zeus-api did not exit within {timeout:?}");
        }
        thread::sleep(Duration::from_millis(25));
    }
}

fn unused_local_address() -> SocketAddr {
    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    listener.local_addr().unwrap()
}

fn unique_fixture_root() -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!(
        "zeus-api-shutdown-test-{}-{nonce}",
        std::process::id()
    ))
}

struct ChildGuard {
    child: Child,
}

impl ChildGuard {
    fn spawn(database: &Path, address: SocketAddr) -> Self {
        let child = Command::new(env!("CARGO_BIN_EXE_zeus-api"))
            .env("ZEUS_DATABASE_PATH", database)
            .env("ZEUS_DEMO_PROFILE", "production-guarded")
            .env("ZEUS_LISTEN_ADDR", address.to_string())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("failed to start zeus-api test process");
        Self { child }
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if matches!(self.child.try_wait(), Ok(None)) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}
