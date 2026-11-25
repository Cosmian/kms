mod middleware;
mod session;
mod token;

use std::time::Duration;

pub(crate) use middleware::AuthVerifier;
pub(crate) use session::AuthVerifierValidator;
#[cfg(test)]
pub(crate) use token::tests as test_helpers;
pub(crate) use token::{
    AUTH_VERIFIER_SESSION_COOKIE, authenticate_auth_verifier_session_cookie,
    verify_auth_verifier_jwt_subject,
};
use url::{Host, Url};

use crate::{error::KmsError, result::KResult};

/// Builder of the HTTP clients the KMS uses to call the Auth Verifier and the Vault-style
/// auth backend: redirects are never followed (SSRF) and a stalled peer cannot hold a
/// request, hence an authentication slot, forever (5 s to connect, 10 s overall).
pub(crate) fn hardened_client_builder(accept_invalid_certs: bool) -> reqwest::ClientBuilder {
    reqwest::Client::builder()
        .danger_accept_invalid_certs(accept_invalid_certs)
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(10))
}

/// Fail unless `url` (the value of the configuration key `setting`) is `https://`, or
/// `http://` towards a loopback host: credentials and session tokens must not cross a
/// network in clear text.
///
/// # Errors
/// When `url` does not parse, or is neither `https` nor `http` on a loopback host.
pub(crate) fn require_https_or_loopback(url: &str, setting: &str) -> KResult<()> {
    let parsed =
        Url::parse(url).map_err(|e| KmsError::ServerError(format!("invalid {setting}: {e}")))?;
    let loopback = match parsed.host() {
        Some(Host::Domain(domain)) => domain.eq_ignore_ascii_case("localhost"),
        Some(Host::Ipv4(ip)) => ip.is_loopback(),
        Some(Host::Ipv6(ip)) => ip.is_loopback(),
        None => false,
    };
    if parsed.scheme() == "https" || (parsed.scheme() == "http" && loopback) {
        Ok(())
    } else {
        Err(KmsError::ServerError(format!(
            "{setting} must use https:// (http:// is accepted only for loopback hosts)"
        )))
    }
}

/// Read the body of `resp`, giving up as soon as it exceeds `max` bytes so that a hostile
/// or broken peer cannot make the KMS buffer an unbounded response.
///
/// # Errors
/// When the body cannot be read, or is longer than `max` bytes.
pub(crate) async fn read_body_capped(
    mut resp: reqwest::Response,
    max: usize,
) -> Result<Vec<u8>, String> {
    let mut body = Vec::new();
    while let Some(chunk) = resp
        .chunk()
        .await
        .map_err(|e| format!("cannot read the response body: {e}"))?
    {
        if body.len().saturating_add(chunk.len()) > max {
            return Err(format!("the response body exceeds {max} bytes"));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };

    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };

    use super::*;

    /// Serve `response` verbatim to every connection on a loopback port; returns the port.
    async fn raw_http_server(response: Vec<u8>, hit: Arc<AtomicBool>) -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let port = listener.local_addr().expect("local address").port();
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                hit.store(true, Ordering::SeqCst);
                let mut buf = vec![0_u8; 4096];
                drop(stream.read(&mut buf).await);
                drop(stream.write_all(&response).await);
            }
        });
        port
    }

    /// A 3xx towards another host must be returned as is, never followed (SSRF).
    #[tokio::test]
    async fn redirect_is_not_followed() {
        let target_hit = Arc::new(AtomicBool::new(false));
        let target_port = raw_http_server(
            b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec(),
            target_hit.clone(),
        )
        .await;
        let redirect = format!(
            "HTTP/1.1 307 Temporary Redirect\r\nLocation: http://127.0.0.1:{target_port}/secret\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        );
        let port = raw_http_server(redirect.into_bytes(), Arc::new(AtomicBool::new(false))).await;

        let response = hardened_client_builder(false)
            .build()
            .expect("client")
            .get(format!("http://127.0.0.1:{port}/whoami"))
            .send()
            .await
            .expect("the redirect response itself is returned");

        assert_eq!(response.status(), reqwest::StatusCode::TEMPORARY_REDIRECT);
        assert!(
            !target_hit.load(Ordering::SeqCst),
            "the redirect target must never be contacted"
        );
    }

    /// A peer that accepts the connection and never answers must make the request fail
    /// (client timeout), not hang.
    #[tokio::test]
    async fn stalled_server_times_out() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let port = listener.local_addr().expect("local address").port();
        tokio::spawn(async move {
            // Keep every accepted connection open without ever writing to it.
            while let Ok((stream, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let _held = stream;
                    tokio::time::sleep(Duration::from_secs(60)).await;
                });
            }
        });
        let client = hardened_client_builder(false).build().expect("client");

        let outcome = tokio::time::timeout(
            Duration::from_secs(15),
            client.get(format!("http://127.0.0.1:{port}/whoami")).send(),
        )
        .await
        .expect("the client timeout (10 s) must fire before the 15 s test guard");

        let error = outcome.expect_err("a stalled server must yield an error");
        assert!(error.is_timeout(), "{error}");
    }

    #[test]
    fn require_https_or_loopback_cases() {
        for ok in [
            "https://auth.example.com/",
            "https://10.0.0.5:8443",
            "http://127.0.0.1:9000",
            "http://localhost:9000/x",
            "http://LOCALHOST",
            "http://[::1]:9000",
        ] {
            require_https_or_loopback(ok, "auth_verifier_url")
                .unwrap_or_else(|e| panic!("{ok} must be accepted: {e}"));
        }
        for bad in [
            "http://auth.example.com/",
            "http://10.0.0.5:8080",
            "http://localhost.example.com",
            "ftp://127.0.0.1",
            "not a url",
        ] {
            let Err(error) = require_https_or_loopback(bad, "auth_verifier_url") else {
                panic!("{bad} must be rejected");
            };
            assert!(error.to_string().contains("auth_verifier_url"), "{error}");
        }
    }

    #[tokio::test]
    async fn read_body_capped_rejects_oversized_bodies() {
        let body = vec![b'a'; 2000];
        let mut response =
            b"HTTP/1.1 200 OK\r\nContent-Length: 2000\r\nConnection: close\r\n\r\n".to_vec();
        response.extend_from_slice(&body);
        let port = raw_http_server(response, Arc::new(AtomicBool::new(false))).await;
        let client = hardened_client_builder(false).build().expect("client");
        let url = format!("http://127.0.0.1:{port}/");

        let over = client.get(&url).send().await.expect("response");
        read_body_capped(over, 1000).await.unwrap_err();

        let within = client.get(&url).send().await.expect("response");
        assert_eq!(read_body_capped(within, 4000).await, Ok(body));
    }
}
