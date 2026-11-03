//! Minimal offline mock of Google's `OAuth2` token endpoint and of the Gmail CSE API.
//!
//! It serves plain HTTP on a loopback port from a dedicated thread (so it also works when the
//! test body blocks, e.g. while running the `ckms` binary) and records every request it receives.

use std::{
    io,
    net::TcpListener as StdTcpListener,
    sync::{Arc, Mutex},
    thread,
};

use cosmian_kms_client::GmailApiConf;
use cosmian_logger::debug;
use openssl::rsa::Rsa;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

const TOKEN_OK: &str = r#"{"access_token":"mock-token","expires_in":3600,"token_type":"Bearer"}"#;
const END_OF_HEADERS: &[u8] = b"\r\n\r\n";

/// A request received by the mock.
#[derive(Debug, Clone)]
pub struct RecordedRequest {
    pub method: String,
    pub path: String,
    pub authorization: Option<String>,
    pub body: String,
}

/// A running mock Google server.
pub struct MockGoogle {
    /// Base URL of the mock, e.g. `http://127.0.0.1:12345`
    pub base: String,
    /// Every request received so far, in arrival order
    pub requests: Arc<Mutex<Vec<RecordedRequest>>>,
}

/// Start the mock on a free loopback port.
///
/// Routes (first match wins):
/// - `/token` -> 200 with an access token
/// - `/token-fail` -> 400 `{"error":"invalid_grant"}`
/// - `/token-notjson` -> 200 with a non-JSON body
/// - path containing `/fail` -> 400 with a Gmail-style JSON error `mock failure`
/// - path containing `/html` -> 500 with an HTML body
/// - anything else -> 200 `{"ok":true}`
///
/// # Panics
/// Panics if no loopback port can be bound.
#[expect(clippy::expect_used)]
#[must_use]
pub fn start() -> MockGoogle {
    let listener = StdTcpListener::bind("127.0.0.1:0").expect("cannot bind the mock Google server");
    listener
        .set_nonblocking(true)
        .expect("cannot set the mock Google listener non-blocking");
    let port = listener
        .local_addr()
        .expect("mock Google listener has no local address")
        .port();
    let requests = Arc::new(Mutex::new(Vec::new()));
    let log = requests.clone();
    thread::spawn(move || {
        let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .build()
        else {
            return;
        };
        runtime.block_on(async move {
            let Ok(listener) = TcpListener::from_std(listener) else {
                return;
            };
            while let Ok((stream, _)) = listener.accept().await {
                let log = log.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle(stream, &log).await {
                        debug!("mock Google: connection error: {e}");
                    }
                });
            }
        });
    });
    MockGoogle {
        base: format!("http://127.0.0.1:{port}"),
        requests,
    }
}

/// A `GmailApiConf` pointing at the mock: the token endpoint is `{base}{token_path}` and the
/// Gmail API is `{base}/gmail/v1/users/`. The private key is a freshly generated RSA key.
///
/// # Panics
/// Panics if the RSA key cannot be generated.
#[expect(clippy::expect_used)]
#[must_use]
pub fn gmail_api_conf(base: &str, token_path: &str) -> GmailApiConf {
    let pem = Rsa::generate(2048)
        .and_then(|rsa| rsa.private_key_to_pem())
        .expect("cannot generate the mock service account key");
    GmailApiConf {
        account_type: "service_account".to_owned(),
        project_id: "mock-project".to_owned(),
        private_key_id: "mock-key-id".to_owned(),
        private_key: String::from_utf8_lossy(&pem).into_owned(),
        client_email: "mock-sa@mock-project.iam.gserviceaccount.com".to_owned(),
        client_id: "1234567890".to_owned(),
        auth_uri: format!("{base}/auth"),
        token_uri: format!("{base}{token_path}"),
        auth_provider_x509_cert_url: format!("{base}/certs"),
        client_x509_cert_url: format!("{base}/x509"),
        universe_domain: "googleapis.com".to_owned(),
        gmail_api_base_url: Some(format!("{base}/gmail/v1/users/")),
    }
}

async fn handle(mut stream: TcpStream, log: &Mutex<Vec<RecordedRequest>>) -> io::Result<()> {
    let mut buf = Vec::new();
    let mut chunk = [0_u8; 4096];
    let headers_end = loop {
        if let Some(pos) = buf
            .windows(END_OF_HEADERS.len())
            .position(|w| w == END_OF_HEADERS)
        {
            break pos;
        }
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        buf.extend_from_slice(chunk.get(..n).unwrap_or_default());
    };
    let head = String::from_utf8_lossy(buf.get(..headers_end).unwrap_or_default()).into_owned();
    let mut lines = head.split("\r\n");
    let mut request_line = lines.next().unwrap_or_default().split(' ');
    let method = request_line.next().unwrap_or_default().to_owned();
    let path = request_line.next().unwrap_or_default().to_owned();
    let mut authorization = None;
    let mut content_length = 0_usize;
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            if name.eq_ignore_ascii_case("authorization") {
                authorization = Some(value.trim().to_owned());
            } else if name.eq_ignore_ascii_case("content-length") {
                content_length = value.trim().parse().unwrap_or_default();
            }
        }
    }

    let body_start = headers_end + END_OF_HEADERS.len();
    while buf.len() < body_start + content_length {
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(chunk.get(..n).unwrap_or_default());
    }
    let body = String::from_utf8_lossy(
        buf.get(body_start..body_start + content_length)
            .unwrap_or_default(),
    )
    .into_owned();

    let (status, content_type, reply) = match path.as_str() {
        "/token" => ("200 OK", "application/json", TOKEN_OK),
        "/token-fail" => (
            "400 Bad Request",
            "application/json",
            r#"{"error":"invalid_grant"}"#,
        ),
        "/token-notjson" => ("200 OK", "application/json", "not json"),
        p if p.contains("/fail") => (
            "400 Bad Request",
            "application/json",
            r#"{"error":{"message":"mock failure"}}"#,
        ),
        p if p.contains("/html") => (
            "500 Internal Server Error",
            "text/html",
            "<html>oops</html>",
        ),
        _ => ("200 OK", "application/json", r#"{"ok":true}"#),
    };

    if let Ok(mut requests) = log.lock() {
        requests.push(RecordedRequest {
            method,
            path,
            authorization,
            body,
        });
    }

    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{reply}",
        reply.len()
    );
    stream.write_all(response.as_bytes()).await?;
    stream.shutdown().await
}
