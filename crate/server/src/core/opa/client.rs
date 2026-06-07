//! OPA HTTP client — fail-closed design.

use reqwest::Client;
use serde::Deserialize;
use tracing::warn;

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
            let body_text = resp.text().await.unwrap_or_default();
            warn!("OPA returned non-2xx (fail-closed deny): {status} — {body_text}");
            return Ok(false);
        }

        let opa_resp: OpaResponse = resp.json().await.map_err(|e| {
            warn!("OPA response parse failed (fail-closed deny): {e}");
            KmsError::ServerError(format!("OPA response parse error: {e}"))
        })?;

        Ok(opa_resp.result.unwrap_or(false))
    }
}
