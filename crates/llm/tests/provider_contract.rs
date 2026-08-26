use std::time::Duration;

use llm::{
    LocalFallbackProvider, OpenAiCompatibleProvider, ProviderError, ReplyKind, ReplyMessage,
    ReplyProvider, ReplyRequest, ReplyRole,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    sync::oneshot,
    task::JoinHandle,
    time::{sleep, timeout},
};

struct CapturedRequest {
    head: String,
    body: Vec<u8>,
}

struct MockServer {
    endpoint: String,
    received: Option<oneshot::Receiver<CapturedRequest>>,
    task: JoinHandle<()>,
}

impl Drop for MockServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn spawn_mock(
    status: &str,
    extra_headers: &[(&str, String)],
    body: impl Into<Vec<u8>>,
    delay: Duration,
) -> MockServer {
    let body = body.into();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (send_request, received) = oneshot::channel();
    let mut response = format!(
        "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n",
        body.len()
    );
    for (name, value) in extra_headers {
        response.push_str(name);
        response.push_str(": ");
        response.push_str(value);
        response.push_str("\r\n");
    }
    response.push_str("\r\n");
    let mut response = response.into_bytes();
    response.extend_from_slice(&body);

    let task = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut request = Vec::new();
        let mut buffer = [0_u8; 4096];
        let header_end = loop {
            let count = socket.read(&mut buffer).await.unwrap();
            if count == 0 {
                return;
            }
            request.extend_from_slice(&buffer[..count]);
            if let Some(index) = request.windows(4).position(|window| window == b"\r\n\r\n") {
                break index + 4;
            }
            assert!(
                request.len() <= 1024 * 1024,
                "mock request header exceeded 1 MiB"
            );
        };
        let head = String::from_utf8(request[..header_end].to_vec()).unwrap();
        let content_length = head
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse::<usize>().unwrap())
            })
            .unwrap_or(0);
        while request.len() - header_end < content_length {
            let count = socket.read(&mut buffer).await.unwrap();
            if count == 0 {
                break;
            }
            request.extend_from_slice(&buffer[..count]);
        }
        let body = request[header_end..header_end + content_length].to_vec();
        let _ = send_request.send(CapturedRequest { head, body });
        sleep(delay).await;
        let _ = socket.write_all(&response).await;
    });

    MockServer {
        endpoint: format!("http://{address}/v1/chat/completions"),
        received: Some(received),
        task,
    }
}

fn request_with_secret(secret: &str) -> ReplyRequest {
    ReplyRequest::new([
        ReplyMessage::new(ReplyRole::System, "Answer concisely."),
        ReplyMessage::new(ReplyRole::User, secret),
    ])
}

#[tokio::test]
async fn local_fallback_is_object_safe_non_model_and_never_echoes_input() {
    let provider: Box<dyn ReplyProvider> = Box::new(LocalFallbackProvider::new());
    let secret = "sk-user-secret-do-not-reflect";

    let response = provider.reply(request_with_secret(secret)).await.unwrap();

    assert_eq!(response.provider.reply_kind, ReplyKind::NonModelFallback);
    assert!(!response.provider.is_model_reply());
    assert!(response.provider.model.is_none());
    assert!(!response.content.contains(secret));
}

#[test]
fn openai_compatible_requires_https_except_for_loopback_development() {
    for endpoint in [
        "http://example.com/v1/chat/completions",
        "http://192.168.1.10/v1/chat/completions",
        "http://0.0.0.0/v1/chat/completions",
    ] {
        assert!(matches!(
            OpenAiCompatibleProvider::new(endpoint, "model", "test-api-key"),
            Err(ProviderError::InvalidConfiguration(
                "plain HTTP endpoints must use a loopback host"
            ))
        ));
    }

    for endpoint in [
        "https://example.com/v1/chat/completions",
        "http://localhost:8080/v1/chat/completions",
        "http://127.0.0.1:8080/v1/chat/completions",
        "http://[::1]:8080/v1/chat/completions",
    ] {
        OpenAiCompatibleProvider::new(endpoint, "model", "test-api-key").unwrap();
    }
}

#[test]
fn openai_compatible_provider_id_binds_non_secret_configuration() {
    let first = OpenAiCompatibleProvider::new(
        "https://one.example/v1/chat/completions",
        "same-model",
        "first-secret",
    )
    .unwrap();
    let other_endpoint = OpenAiCompatibleProvider::new(
        "https://two.example/v1/chat/completions",
        "same-model",
        "first-secret",
    )
    .unwrap();
    let rotated_secret = OpenAiCompatibleProvider::new(
        "https://one.example/v1/chat/completions",
        "same-model",
        "second-secret",
    )
    .unwrap();

    assert_ne!(
        first.metadata().provider_id,
        other_endpoint.metadata().provider_id
    );
    assert_eq!(
        first.metadata().provider_id,
        rotated_secret.metadata().provider_id,
        "credential rotation must not be encoded into durable metadata"
    );
    assert!(
        first
            .metadata()
            .provider_id
            .starts_with("openai-compatible:")
    );
    assert!(!first.metadata().provider_id.contains("one.example"));
    assert!(!first.metadata().provider_id.contains("first-secret"));
}

#[tokio::test]
async fn openai_compatible_success_sends_bearer_model_and_messages() {
    let response = serde_json::json!({
        "choices": [{
            "message": { "role": "assistant", "content": "Mock reply" },
            "finish_reason": "stop"
        }]
    });
    let mut mock = spawn_mock(
        "200 OK",
        &[("Content-Type", "application/json".to_owned())],
        serde_json::to_vec(&response).unwrap(),
        Duration::ZERO,
    )
    .await;
    let provider =
        OpenAiCompatibleProvider::new(&mock.endpoint, "mock-model", "test-api-key").unwrap();

    let reply = provider
        .reply(request_with_secret("Hello provider"))
        .await
        .unwrap();
    let captured = mock.received.take().unwrap().await.unwrap();
    let request_json: serde_json::Value = serde_json::from_slice(&captured.body).unwrap();

    assert_eq!(reply.content, "Mock reply");
    assert_eq!(reply.finish_reason.as_deref(), Some("stop"));
    assert!(reply.provider.is_model_reply());
    assert_eq!(reply.provider.model.as_deref(), Some("mock-model"));
    assert!(
        captured
            .head
            .to_ascii_lowercase()
            .contains("\r\nauthorization: bearer test-api-key\r\n")
    );
    assert_eq!(request_json["model"], "mock-model");
    assert_eq!(request_json["messages"][1]["role"], "user");
    assert_eq!(request_json["messages"][1]["content"], "Hello provider");
}

#[tokio::test]
async fn openai_compatible_unauthorized_fails_without_parsing_or_fallback() {
    let mock = spawn_mock(
        "401 Unauthorized",
        &[("Content-Type", "application/json".to_owned())],
        br#"{"error":{"message":"bad key"}}"#.to_vec(),
        Duration::ZERO,
    )
    .await;
    let provider =
        OpenAiCompatibleProvider::new(&mock.endpoint, "mock-model", "wrong-key").unwrap();

    let result = provider.reply(request_with_secret("private prompt")).await;

    assert_eq!(result, Err(ProviderError::HttpStatus { status: 401 }));
}

#[tokio::test]
async fn openai_compatible_times_out_the_complete_operation() {
    let mock = spawn_mock(
        "200 OK",
        &[("Content-Type", "application/json".to_owned())],
        br#"{"choices":[{"message":{"content":"late"}}]}"#.to_vec(),
        Duration::from_millis(250),
    )
    .await;
    let provider = OpenAiCompatibleProvider::with_limits(
        &mock.endpoint,
        "mock-model",
        "test-api-key",
        Duration::from_millis(40),
        1024,
    )
    .unwrap();

    let result = provider.reply(request_with_secret("private prompt")).await;

    assert_eq!(result, Err(ProviderError::Timeout));
}

#[tokio::test]
async fn openai_compatible_refuses_oversized_response_before_json_parsing() {
    let mock = spawn_mock(
        "200 OK",
        &[("Content-Type", "application/json".to_owned())],
        vec![b'x'; 512],
        Duration::ZERO,
    )
    .await;
    let provider = OpenAiCompatibleProvider::with_limits(
        &mock.endpoint,
        "mock-model",
        "test-api-key",
        Duration::from_secs(1),
        128,
    )
    .unwrap();

    let result = provider.reply(request_with_secret("private prompt")).await;

    assert_eq!(
        result,
        Err(ProviderError::ResponseTooLarge { limit_bytes: 128 })
    );
}

#[tokio::test]
async fn openai_compatible_rejects_oversized_content_inside_a_bounded_http_body() {
    let response = serde_json::json!({
        "choices": [{
            "message": {
                "role": "assistant",
                "content": "x".repeat(protocol::ASSISTANT_MESSAGE_MAX_BYTES + 1),
            },
            "finish_reason": "stop",
        }]
    });
    let mock = spawn_mock(
        "200 OK",
        &[("Content-Type", "application/json".to_owned())],
        serde_json::to_vec(&response).unwrap(),
        Duration::ZERO,
    )
    .await;
    let provider =
        OpenAiCompatibleProvider::new(&mock.endpoint, "mock-model", "test-api-key").unwrap();

    assert_eq!(
        provider.reply(request_with_secret("private prompt")).await,
        Err(ProviderError::TerminalPayloadTooLarge {
            limit_bytes: protocol::ASSISTANT_MESSAGE_MAX_BYTES,
        })
    );
}

#[tokio::test]
async fn openai_compatible_never_follows_redirects() {
    let mut target = spawn_mock(
        "200 OK",
        &[("Content-Type", "application/json".to_owned())],
        br#"{"choices":[{"message":{"content":"must not arrive"}}]}"#.to_vec(),
        Duration::ZERO,
    )
    .await;
    let redirect = spawn_mock(
        "302 Found",
        &[("Location", target.endpoint.clone())],
        Vec::new(),
        Duration::ZERO,
    )
    .await;
    let provider =
        OpenAiCompatibleProvider::new(&redirect.endpoint, "mock-model", "test-api-key").unwrap();

    let result = provider.reply(request_with_secret("private prompt")).await;

    assert_eq!(result, Err(ProviderError::HttpStatus { status: 302 }));
    assert!(
        timeout(Duration::from_millis(100), target.received.take().unwrap(),)
            .await
            .is_err(),
        "redirect target unexpectedly received the credential-bearing request"
    );
}
