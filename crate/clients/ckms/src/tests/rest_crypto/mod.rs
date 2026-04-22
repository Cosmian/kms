mod encrypt_decrypt;
mod error_cases;
mod mac;
mod sign_verify;

use crate::error::result::CosmianResult;

/// Build a reqwest client that does not follow redirects and does not verify TLS
/// (the test server uses plain HTTP).
pub(super) fn test_http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .no_proxy()
        .build()
        .expect("failed to build reqwest client")
}

/// Base URL for the REST crypto API given a test-server port.
pub(super) fn base_url(port: u16) -> String {
    format!("http://127.0.0.1:{port}/v1/crypto")
}
