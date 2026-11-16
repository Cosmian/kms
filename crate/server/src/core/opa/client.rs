//! OPA HTTP client — fail-closed design.

use reqwest::Client;
use serde::Deserialize;
use tracing::{debug, warn};

use super::OpaInput;
use crate::{error::KmsError, result::KResult};

/// Wrapper around the OPA REST API.
///
/// Evaluates the KMS RBAC policy at `POST /v1/data/kms/allow`.
/// Fail-closed: any transport or parsing error results in denial.
pub(crate) struct OpaClient {
    client: Client,
    /// Full URL to the OPA decision endpoint (e.g. `http://localhost:8181/v1/data/kms/allow`).
    decision_url: String,
}

/// OPA response shape for a simple boolean policy.
#[derive(Deserialize)]
struct OpaResponse {
    result: Option<bool>,
}

/// Wrapper for the `input` field required by the OPA Data API.
#[derive(serde::Serialize)]
struct OpaRequest<'a> {
    input: &'a OpaInput,
}

impl OpaClient {
    /// Create a new OPA client targeting the given base URL.
    ///
    /// The base URL should be the OPA server root (e.g. `http://localhost:8181`).
    /// The decision path `/v1/data/kms/allow` is appended automatically.
    pub(crate) fn new(base_url: &str) -> KResult<Self> {
        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            // The decision must come from the configured endpoint only: never let a
            // misconfigured or compromised OPA endpoint bounce the request to another host.
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| KmsError::ServerError(format!("OPA client init failed: {e}")))?;
        let decision_url = format!("{}/v1/data/kms/allow", base_url.trim_end_matches('/'));
        Ok(Self {
            client,
            decision_url,
        })
    }

    /// Query OPA for a decision. Returns `true` if allowed, `false` if denied.
    ///
    /// Any error (network, timeout, parse failure) is treated as denial (fail-closed).
    pub(crate) async fn query(&self, input: &OpaInput) -> KResult<bool> {
        let body = OpaRequest { input };
        let resp = self
            .client
            .post(&self.decision_url)
            .json(&body)
            .send()
            .await
            .map_err(|e| {
                warn!("OPA request failed (fail-closed deny): {e}");
                KmsError::ServerError(format!("OPA unreachable: {e}"))
            })?;

        if !resp.status().is_success() {
            let status = resp.status();
            // The body is peer-controlled text: keep it out of the default log level and
            // escape it so it cannot forge log lines.
            let body_text = resp.text().await.unwrap_or_default();
            warn!("OPA returned non-2xx (fail-closed deny): {status}");
            debug!("OPA non-2xx response body: {body_text:?}");
            return Ok(false);
        }

        let opa_resp: OpaResponse = resp.json().await.map_err(|e| {
            warn!("OPA response parse failed (fail-closed deny): {e}");
            KmsError::ServerError(format!("OPA response parse error: {e}"))
        })?;

        Ok(opa_resp.result.unwrap_or(false))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };

    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, TcpStream},
    };

    use super::*;

    // ── OpaClient::new — URL construction ────────────────────────────────────
    //
    // These tests exercise `OpaClient::new` without making any network calls.
    // They verify that the decision URL is assembled correctly so that
    // `OpaClient::query` will hit the right OPA REST endpoint.

    /// The decision URL is formed as `{base_url}/v1/data/kms/allow`.
    #[test]
    fn test_opa_client_new_constructs_correct_decision_url() {
        let client = OpaClient::new("http://localhost:8181")
            .expect("OpaClient::new must succeed with a valid URL");
        assert_eq!(
            client.decision_url,
            "http://localhost:8181/v1/data/kms/allow"
        );
    }

    /// A trailing `/` on the base URL is stripped before appending the path,
    /// so `http://opa:8181/` and `http://opa:8181` produce identical URLs.
    #[test]
    fn test_opa_client_new_trims_trailing_slash() {
        let client = OpaClient::new("http://opa:8181/").expect("OpaClient::new must succeed");
        assert_eq!(
            client.decision_url, "http://opa:8181/v1/data/kms/allow",
            "trailing slash must be removed before appending path"
        );
    }

    /// Base URL with a path prefix is handled correctly (custom OPA mount point).
    #[test]
    fn test_opa_client_new_preserves_path_prefix() {
        let client =
            OpaClient::new("http://opa:8181/kms-opa").expect("OpaClient::new must succeed");
        assert_eq!(
            client.decision_url,
            "http://opa:8181/kms-opa/v1/data/kms/allow"
        );
    }

    // ── OpaResponse deserialization ──────────────────────────────────────────

    /// `{"result": true}` deserializes as `Some(true)`.
    #[test]
    fn test_opa_response_result_true() {
        let r: OpaResponse = serde_json::from_str(r#"{"result":true}"#).unwrap();
        assert_eq!(r.result, Some(true));
    }

    /// `{"result": false}` deserializes as `Some(false)`.
    #[test]
    fn test_opa_response_result_false() {
        let r: OpaResponse = serde_json::from_str(r#"{"result":false}"#).unwrap();
        assert_eq!(r.result, Some(false));
    }

    /// `{}` (missing `result` key — undefined Rego rule) deserializes as `None`,
    /// which `query()` maps to `false` (fail-closed).
    #[test]
    fn test_opa_response_missing_result_is_none() {
        let r: OpaResponse = serde_json::from_str("{}").unwrap();
        assert!(
            r.result.is_none(),
            "missing result must deserialize as None"
        );
    }

    /// `{"result": null}` (undefined OPA policy) deserializes as `None`.
    #[test]
    fn test_opa_response_null_result_is_none() {
        let r: OpaResponse = serde_json::from_str(r#"{"result":null}"#).unwrap();
        assert!(r.result.is_none());
    }

    // ── query() against a stub OPA endpoint ──────────────────────────────────

    fn sample_input() -> OpaInput {
        OpaInput {
            user: "alice@acme.com".to_owned(),
            user_domain: "acme".to_owned(),
            roles: vec!["User".to_owned()],
            operation: "get".to_owned(),
            object_uid: "uid-001".to_owned(),
            object_domain: "acme".to_owned(),
            is_owner: false,
        }
    }

    fn http_response(status: &str, extra_headers: &str, body: &str) -> String {
        format!(
            "HTTP/1.1 {status}\r\n{extra_headers}Content-Type: application/json\r\n\
             Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
    }

    /// Read one whole HTTP/1.1 request (headers and `Content-Length` body) before the stub
    /// answers: replying and closing while request bytes are unread can reset the connection,
    /// and the client would then report a transport error instead of the response under test.
    async fn read_request(stream: &mut TcpStream) {
        let mut request = Vec::new();
        let mut chunk = [0_u8; 1024];
        loop {
            let read = stream.read(&mut chunk).await.unwrap_or(0);
            let Some(bytes) = chunk.get(..read).filter(|bytes| !bytes.is_empty()) else {
                break;
            };
            request.extend_from_slice(bytes);
            let text = String::from_utf8_lossy(&request);
            if let Some((head, body)) = text.split_once("\r\n\r\n") {
                let announced = head
                    .lines()
                    .filter_map(|line| line.split_once(':'))
                    .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
                    .and_then(|(_, value)| value.trim().parse::<usize>().ok())
                    .unwrap_or(0);
                if body.len() >= announced {
                    break;
                }
            }
        }
    }

    /// Spawn a one-shot HTTP server on a loopback port: it raises `hit` when a client connects
    /// and answers the first request with `response`. Returns the server base URL.
    async fn one_shot_server(response: String, hit: Arc<AtomicBool>) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            if let Ok((mut stream, _)) = listener.accept().await {
                hit.store(true, Ordering::SeqCst);
                read_request(&mut stream).await;
                stream.write_all(response.as_bytes()).await.unwrap();
            }
        });
        format!("http://127.0.0.1:{port}")
    }

    /// Control for the redirect test below: the stub endpoint's decision is honoured.
    #[tokio::test]
    async fn test_opa_query_returns_the_endpoint_decision() {
        let server = one_shot_server(
            http_response("200 OK", "", r#"{"result":true}"#),
            Arc::new(AtomicBool::new(false)),
        )
        .await;
        let client = OpaClient::new(&server).unwrap();
        assert!(client.query(&sample_input()).await.unwrap());
    }

    /// A redirect from the OPA endpoint must not be followed: the decision input (identity,
    /// roles, object) would be replayed to another host whose answer would then be trusted as
    /// the authorization decision. The redirect itself is a non-2xx answer, hence a denial.
    #[tokio::test]
    async fn test_opa_redirect_is_not_followed_and_denies() {
        // Would approve every request if the client ever reached it.
        let target_hit = Arc::new(AtomicBool::new(false));
        let target = one_shot_server(
            http_response("200 OK", "", r#"{"result":true}"#),
            Arc::clone(&target_hit),
        )
        .await;
        let redirector = one_shot_server(
            http_response(
                "307 Temporary Redirect",
                &format!("Location: {target}/v1/data/kms/allow\r\n"),
                "",
            ),
            Arc::new(AtomicBool::new(false)),
        )
        .await;

        let client = OpaClient::new(&redirector).unwrap();
        let allowed = client
            .query(&sample_input())
            .await
            .expect("a redirect is a denial, not a transport error");

        assert!(!allowed, "a redirecting OPA endpoint must yield a denial");
        assert!(
            !target_hit.load(Ordering::SeqCst),
            "the redirect target must never be contacted"
        );
    }
}
