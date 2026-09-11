use std::{
    future::Future,
    time::Duration,
};

use pulsevm_core::crypto::PrivateKey;
use serde_json::{
    Value,
    json,
};
use tokio::{
    io::{
        AsyncRead,
        AsyncReadExt,
        AsyncWrite,
        AsyncWriteExt,
    },
    net::TcpListener,
    time::timeout,
};

use super::{
    ClientError,
    KeosdClient,
    KeosdErrorResponse,
    parse_http_response,
    types::SignedKeosdTransaction,
};

#[derive(Clone, Copy)]
enum Connection {
    Tcp,
    #[cfg(unix)]
    Unix,
}

fn connections() -> Vec<Connection> {
    vec![
        Connection::Tcp,
        #[cfg(unix)]
        Connection::Unix,
    ]
}

fn response(status: u16, body: &[u8]) -> Vec<u8> {
    let mut raw = format!(
        "HTTP/1.1 {status} Test\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .into_bytes();
    raw.extend_from_slice(body);
    raw
}

async fn serve<S: AsyncRead + AsyncWrite + Unpin>(
    mut stream: S,
    method: &str,
    path: &str,
    body: Option<Value>,
    reply: Vec<u8>,
) {
    let mut request = Vec::new();
    let mut chunk = [0; 1024];
    let header_end = loop {
        let count = stream.read(&mut chunk).await.unwrap();
        assert_ne!(count, 0, "client closed before sending request headers");
        request.extend_from_slice(&chunk[..count]);
        assert!(
            request.len() <= 64 * 1024,
            "unexpectedly large test request"
        );
        if let Some(end) = request.windows(4).position(|bytes| bytes == b"\r\n\r\n") {
            break end + 4;
        }
    };
    let headers = std::str::from_utf8(&request[..header_end]).unwrap();
    assert_eq!(
        headers.lines().next().unwrap(),
        format!("{method} {path} HTTP/1.1")
    );
    let content_length = headers
        .lines()
        .filter_map(|line| line.split_once(':'))
        .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
        .map(|(_, value)| value.trim().parse::<usize>().unwrap())
        .unwrap_or(0);
    assert!(content_length <= 64 * 1024);
    if body.is_some() {
        assert!(headers.lines().any(|line| {
            line.split_once(':').is_some_and(|(name, value)| {
                name.eq_ignore_ascii_case("content-type") && value.trim() == "application/json"
            })
        }));
    }
    while request.len() < header_end + content_length {
        let count = stream.read(&mut chunk).await.unwrap();
        assert_ne!(count, 0, "client closed before sending the JSON body");
        request.extend_from_slice(&chunk[..count]);
    }
    let actual_body = &request[header_end..];
    assert_eq!(actual_body.len(), content_length);
    if let Some(body) = body {
        assert_eq!(serde_json::from_slice::<Value>(actual_body).unwrap(), body);
    } else {
        assert!(actual_body.is_empty());
    }
    stream.write_all(&reply).await.unwrap();
    stream.shutdown().await.unwrap();
}

// Bind before starting the client; no sleeps, fixed ports, or external daemon.
// The timeout only bounds a broken test's wait, not the behavior being asserted.
async fn with_response<F, Fut>(
    connection: Connection,
    method: &'static str,
    path: &'static str,
    body: Option<Value>,
    reply: Vec<u8>,
    check: F,
) where
    F: FnOnce(KeosdClient) -> Fut,
    Fut: Future<Output = ()>,
{
    let socket_dir = tempfile::tempdir().unwrap();
    let (client, server) = match connection {
        Connection::Tcp => {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let client = KeosdClient::tcp(&format!("http://{}///", listener.local_addr().unwrap()));
            let server = tokio::spawn(async move {
                let (stream, _) = listener.accept().await.unwrap();
                serve(stream, method, path, body, reply).await;
            });
            (client, server)
        }
        #[cfg(unix)]
        Connection::Unix => {
            let path_on_disk = socket_dir.path().join("wallet.sock");
            let listener = tokio::net::UnixListener::bind(&path_on_disk).unwrap();
            let client = KeosdClient::unix(&path_on_disk);
            let server = tokio::spawn(async move {
                let (stream, _) = listener.accept().await.unwrap();
                serve(stream, method, path, body, reply).await;
            });
            (client, server)
        }
    };
    timeout(Duration::from_secs(30), async {
        let ((), result) = tokio::join!(check(client), server);
        result.unwrap();
    })
    .await
    .expect("mock wallet request did not complete");
    drop(socket_dir);
}

macro_rules! wallet_endpoint_test {
    ($name:ident, $method:ident($($arg:expr),*), $path:literal, $body:expr, $result:expr) => {
        #[tokio::test]
        async fn $name() {
            for connection in connections() {
                let expected = $result;
                let reply = response(200, &serde_json::to_vec(&expected).unwrap());
                with_response(connection, "POST", $path, Some($body), reply, |client| async move {
                    let result = client.$method($($arg),*).await.unwrap();
                    assert_eq!(serde_json::to_value(result).unwrap(), expected);
                }).await;
            }
        }
    };
}

wallet_endpoint_test!(
    create_wallet,
    create("trésor\""),
    "/v1/wallet/create",
    json!("trésor\""),
    json!("PW-test-password")
);
wallet_endpoint_test!(
    open_wallet,
    open("savings"),
    "/v1/wallet/open",
    json!("savings"),
    Value::Null
);
wallet_endpoint_test!(
    lock_wallet,
    lock("savings"),
    "/v1/wallet/lock",
    json!("savings"),
    Value::Null
);
wallet_endpoint_test!(
    lock_all_wallets,
    lock_all(),
    "/v1/wallet/lock_all",
    Value::Null,
    Value::Null
);
wallet_endpoint_test!(
    unlock_wallet,
    unlock("savings", "test-password"),
    "/v1/wallet/unlock",
    json!(["savings", "test-password"]),
    Value::Null
);
wallet_endpoint_test!(
    import_wallet_key,
    import_key("savings", "test-wif"),
    "/v1/wallet/import_key",
    json!(["savings", "test-wif"]),
    Value::Null
);
wallet_endpoint_test!(
    remove_wallet_key,
    remove_key("savings", "test-password", "test-public-key"),
    "/v1/wallet/remove_key",
    json!(["savings", "test-password", "test-public-key"]),
    Value::Null
);
wallet_endpoint_test!(
    create_wallet_key,
    create_key("savings", "R1"),
    "/v1/wallet/create_key",
    json!(["savings", "R1"]),
    json!("test-public-key")
);
wallet_endpoint_test!(
    list_wallets,
    list_wallets(),
    "/v1/wallet/list_wallets",
    Value::Null,
    json!(["savings *", "locked"])
);
wallet_endpoint_test!(
    list_wallet_keys,
    list_keys("savings", "test-password"),
    "/v1/wallet/list_keys",
    json!(["savings", "test-password"]),
    json!([["test-public-key", "test-private-key"]])
);
wallet_endpoint_test!(
    get_public_keys,
    get_public_keys(),
    "/v1/wallet/get_public_keys",
    Value::Null,
    json!(["test-key-1", "test-key-2"])
);
wallet_endpoint_test!(
    get_no_public_keys,
    get_public_keys(),
    "/v1/wallet/get_public_keys",
    Value::Null,
    json!([])
);
wallet_endpoint_test!(
    set_zero_timeout,
    set_timeout(0),
    "/v1/wallet/set_timeout",
    json!(0),
    Value::Null
);
wallet_endpoint_test!(
    set_maximum_timeout,
    set_timeout(u64::MAX),
    "/v1/wallet/set_timeout",
    json!(u64::MAX),
    Value::Null
);
wallet_endpoint_test!(
    sign_digest,
    sign_digest("0123456789abcdef", "test-public-key"),
    "/v1/wallet/sign_digest",
    json!(["0123456789abcdef", "test-public-key"]),
    json!("test-signature")
);
wallet_endpoint_test!(
    stop_daemon,
    stop(),
    "/v1/keosd/stop",
    Value::Null,
    Value::Null
);

#[tokio::test]
async fn sign_transaction_preserves_parameters_and_decodes_signatures() {
    for connection in connections() {
        let key = PrivateKey::new_k1_from_string("keosd-client-test-only").unwrap();
        let signature = key.sign(&Default::default()).unwrap();
        let public_keys = vec![key.get_public_key().to_string()];
        let chain_id = "ab".repeat(32);
        let transaction =
            json!({"expiration": "2026-01-01T00:00:00", "actions": [], "ref_block_num": 42});
        let body = json!([transaction, public_keys, chain_id]);
        let reply = response(
            200,
            &serde_json::to_vec(&json!({
                "signatures": [signature, signature],
                "expiration": "2026-01-01T00:00:00"
            }))
            .unwrap(),
        );
        with_response(
            connection,
            "POST",
            "/v1/wallet/sign_transaction",
            Some(body),
            reply,
            |client| async move {
                let signed = client
                    .sign_transaction(&transaction, &public_keys, &chain_id)
                    .await
                    .unwrap();
                assert_eq!(signed.signatures, vec![signature.clone(), signature]);
            },
        )
        .await;
    }
}

#[tokio::test]
async fn get_and_empty_post_helpers_use_the_expected_wire_format() {
    for connection in connections() {
        with_response(
            connection,
            "GET",
            "/v1/test",
            None,
            response(200, b"[1,2]"),
            |client| async move {
                assert_eq!(
                    client.get_request::<Vec<u32>>("/v1/test").await.unwrap(),
                    vec![1, 2]
                );
            },
        )
        .await;
        with_response(
            connection,
            "POST",
            "/v1/test",
            Some(Value::Null),
            response(200, b"true"),
            |client| async move {
                assert!(client.post_empty::<bool>("/v1/test").await.unwrap());
            },
        )
        .await;
    }
}

fn wallet_error() -> Value {
    json!({
        "code": 500,
        "message": "Internal Service Error",
        "error": {
            "code": 3120003,
            "name": "wallet_locked_exception",
            "what": "Wallet locked",
            "details": [{"message": "Unlock the wallet", "file": "wallet.rs", "line_number": 42, "method": "sign"}]
        }
    })
}

#[tokio::test]
async fn wallet_errors_propagate_through_both_transports() {
    for connection in connections() {
        with_response(
            connection,
            "POST",
            "/v1/wallet/open",
            Some(json!("locked")),
            response(500, &serde_json::to_vec(&wallet_error()).unwrap()),
            |client| async move {
                let error = client.open("locked").await.unwrap_err();
                assert_eq!(
                    error.to_string(),
                    "keosd error 3120003: wallet_locked_exception - Wallet locked"
                );
                let ClientError::Keosd {
                    code,
                    name,
                    what,
                    details,
                } = error
                else {
                    panic!("expected a structured wallet error");
                };
                assert_eq!(code, 3120003);
                assert_eq!(name, "wallet_locked_exception");
                assert_eq!(what, "Wallet locked");
                assert_eq!(details.len(), 1);
                assert_eq!(details[0].message, "Unlock the wallet");
                assert_eq!(details[0].file, "wallet.rs");
                assert_eq!(details[0].line_number, 42);
                assert_eq!(details[0].method, "sign");
            },
        )
        .await;
    }
}

#[tokio::test]
async fn malformed_success_and_plain_http_errors_propagate() {
    for connection in connections() {
        for (status, body) in [(200, &b"not json"[..]), (503, &b"unavailable"[..])] {
            with_response(connection, "POST", "/v1/wallet/create", Some(json!("savings")), response(status, body), |client| async move {
                let error = client.create("savings").await.unwrap_err();
                if status == 200 {
                    assert!(matches!(error, ClientError::Parse(ref message) if message.contains("raw body: not json")));
                } else {
                    assert!(matches!(error, ClientError::Http(ref message) if message == "HTTP 503: unavailable"));
                }
            }).await;
        }
    }
}

#[tokio::test]
async fn stop_propagates_wallet_and_parse_errors() {
    for connection in connections() {
        for (status, body) in [
            (500, serde_json::to_vec(&wallet_error()).unwrap()),
            (200, b"not json".to_vec()),
        ] {
            with_response(
                connection,
                "POST",
                "/v1/keosd/stop",
                Some(Value::Null),
                response(status, &body),
                |client| async move {
                    let error = client.stop().await.unwrap_err();
                    assert!(matches!(
                        (status, error),
                        (500, ClientError::Keosd { .. }) | (200, ClientError::Parse(_))
                    ));
                },
            )
            .await;
        }
    }
}

#[tokio::test]
async fn tcp_connection_closed_without_response_is_only_ignored_for_stop() {
    with_response(
        Connection::Tcp,
        "POST",
        "/v1/wallet/create",
        Some(json!("savings")),
        vec![],
        |client| async move {
            assert!(matches!(
                client.create("savings").await,
                Err(ClientError::Http(_))
            ));
        },
    )
    .await;
    with_response(
        Connection::Tcp,
        "POST",
        "/v1/keosd/stop",
        Some(Value::Null),
        vec![],
        |client| async move {
            client.stop().await.unwrap();
        },
    )
    .await;
}

#[tokio::test]
async fn tcp_truncated_response_body_is_a_transport_error() {
    for method in ["POST", "GET"] {
        with_response(
            Connection::Tcp,
            method,
            "/v1/test",
            (method == "POST").then_some(Value::Null),
            b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\nConnection: close\r\n\r\n{}".to_vec(),
            |client| async move {
                let result = if method == "POST" {
                    client.post_empty::<Value>("/v1/test").await
                } else {
                    client.get_request::<Value>("/v1/test").await
                };
                assert!(matches!(result, Err(ClientError::Http(_))));
            },
        )
        .await;
    }
}

#[tokio::test]
async fn invalid_tcp_url_reports_a_transport_error() {
    let client = KeosdClient::tcp("not a URL");
    assert!(matches!(
        client.create("savings").await,
        Err(ClientError::Http(_))
    ));
    assert!(matches!(
        client.get_request::<Value>("/v1/test").await,
        Err(ClientError::Http(_))
    ));
}

#[cfg(unix)]
#[tokio::test]
async fn missing_unix_socket_reports_io_errors_except_during_stop() {
    let dir = tempfile::tempdir().unwrap();
    let client = KeosdClient::unix(dir.path().join("missing.sock"));
    assert!(matches!(
        client.create("savings").await,
        Err(ClientError::UnixSocket(_))
    ));
    assert!(matches!(
        client.get_request::<Value>("/v1/test").await,
        Err(ClientError::UnixSocket(_))
    ));
    client.stop().await.unwrap();
}

#[cfg(unix)]
#[tokio::test]
async fn malformed_unix_http_response_is_a_parse_error() {
    with_response(
        Connection::Unix,
        "POST",
        "/v1/wallet/create",
        Some(json!("savings")),
        b"not HTTP".to_vec(),
        |client| async move {
            assert!(matches!(
                client.create("savings").await,
                Err(ClientError::Parse(_))
            ));
        },
    )
    .await;
}

#[test]
fn http_parser_rejects_missing_headers_and_invalid_status() {
    for (raw, message) in [
        ("", "no header terminator"),
        ("HTTP/1.1 200 OK\r\n", "no header terminator"),
        ("\r\n\r\n", "Empty HTTP response"),
        ("HTTP/1.1\r\n\r\n", "Cannot parse status"),
        ("HTTP/1.1 invalid Test\r\n\r\n", "Cannot parse status"),
        ("HTTP/1.1 65536 Test\r\n\r\n", "Cannot parse status"),
    ] {
        assert!(
            matches!(parse_http_response(raw.as_bytes()), Err(ClientError::Parse(error)) if error.contains(message)),
            "{raw:?}"
        );
    }
}

#[test]
fn http_parser_preserves_binary_body_and_empty_body() {
    for body in [&b"\xff\x00\r\n\r\nbody"[..], &b""[..]] {
        assert_eq!(
            parse_http_response(&response(200, body)).unwrap(),
            (200, body.to_vec())
        );
    }
}

#[test]
fn response_status_success_boundaries_and_error_fallback() {
    let client = KeosdClient::tcp("http://localhost");
    for status in [200, 201, 299] {
        assert_eq!(
            client
                .handle_response::<Vec<u32>>(status, b"[1,2]")
                .unwrap(),
            vec![1, 2]
        );
    }
    for status in [199, 300, 404, 500] {
        let error = client
            .handle_response::<Value>(status, b"unavailable")
            .unwrap_err();
        assert_eq!(
            error.to_string(),
            format!("HTTP error: HTTP {status}: unavailable")
        );
    }
    assert!(matches!(
        client.handle_response::<Value>(500, b"{\"error\":{}}"),
        Err(ClientError::Http(_))
    ));
}

#[test]
fn success_responses_reject_invalid_json_and_unexpected_types() {
    let client = KeosdClient::tcp("http://localhost");
    for body in [
        &b""[..],
        &b"null"[..],
        &b"{}"[..],
        &b"["[..],
        &b"\xff"[..],
        &b"\"ok\" trailing"[..],
    ] {
        let error = client.handle_response::<String>(200, body).unwrap_err();
        assert!(matches!(error, ClientError::Parse(ref message) if message.contains("raw body:")));
    }
}

#[test]
fn wallet_error_details_default_when_omitted() {
    let mut body = wallet_error();
    body["error"].as_object_mut().unwrap().remove("details");
    let error: KeosdErrorResponse = serde_json::from_value(body.clone()).unwrap();
    assert_eq!(error.code, 500);
    assert_eq!(error.message, "Internal Service Error");
    assert!(error.error.details.is_empty());

    body["error"]["details"] = json!([{"message": "minimal detail"}]);
    let error: KeosdErrorResponse = serde_json::from_value(body).unwrap();
    let detail = &error.error.details[0];
    assert_eq!(detail.message, "minimal detail");
    assert_eq!(detail.file, "");
    assert_eq!(detail.line_number, 0);
    assert_eq!(detail.method, "");
}

#[test]
fn signed_transactions_require_a_valid_signature_list() {
    let signed: SignedKeosdTransaction = serde_json::from_value(json!({"signatures": []})).unwrap();
    assert!(signed.signatures.is_empty());
    let client = KeosdClient::tcp("http://localhost");
    for body in [
        json!({}),
        json!({"signatures": null}),
        json!({"signatures": ["invalid-signature"]}),
    ] {
        assert!(matches!(
            client.handle_response::<SignedKeosdTransaction>(
                200,
                &serde_json::to_vec(&body).unwrap()
            ),
            Err(ClientError::Parse(_))
        ));
    }
}

#[test]
fn error_conversions_preserve_context_and_display_prefixes() {
    let parse_error = serde_json::from_str::<Value>("{").unwrap_err();
    let message = parse_error.to_string();
    let error = ClientError::from(parse_error);
    assert!(matches!(&error, ClientError::Parse(detail) if detail == &message));
    assert_eq!(
        error.to_string(),
        format!("Response parse error: {message}")
    );

    let io_error = std::io::Error::new(std::io::ErrorKind::ConnectionReset, "test peer closed");
    let error = ClientError::from(io_error);
    assert!(matches!(&error, ClientError::UnixSocket(detail) if detail == "test peer closed"));
    assert_eq!(error.to_string(), "Unix socket error: test peer closed");
}
