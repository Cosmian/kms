use cosmian_logger::{debug, warn};
use reqwest::Client;

use crate::{RbacResult, engine::RbacEngine, error::RbacError, input::RbacInput};

/// OPA response structure.
#[derive(serde::Deserialize)]
struct OpaResponse {
    result: bool,
}

/// RBAC engine that delegates evaluation to an external OPA server over HTTP.
///
/// The OPA server is expected to expose a REST API at
/// `{base_url}/v1/data/cosmian/kms/rbac/allow` that accepts a JSON body
/// with an `input` field and returns `{"result": true|false}`.
pub struct ExternalOpaEngine {
    /// HTTP client for calling OPA
    client: Client,
    /// Full URL of the OPA decision endpoint
    decision_url: String,
}

impl ExternalOpaEngine {
    /// Create a new external OPA engine.
    ///
    /// # Arguments
    /// * `base_url` — The OPA server base URL (e.g. `http://localhost:8181`).
    ///   The decision path `/v1/data/cosmian/kms/rbac/allow` is appended automatically.
    #[must_use]
    pub fn new(base_url: &str) -> Self {
        let base = base_url.trim_end_matches('/');
        let decision_url = format!("{base}/v1/data/cosmian/kms/rbac/allow");

        Self {
            client: Client::new(),
            decision_url,
        }
    }

    /// Evaluate asynchronously (for use in async contexts).
    ///
    /// This is the underlying async implementation used by the synchronous
    /// [`RbacEngine::evaluate`] trait method via `tokio::task::block_in_place`.
    async fn evaluate_async(&self, input: &RbacInput) -> RbacResult<bool> {
        let body = serde_json::json!({ "input": input });

        debug!("RBAC: calling external OPA at {}", self.decision_url);

        let response = self
            .client
            .post(&self.decision_url)
            .json(&body)
            .send()
            .await
            .map_err(|e| {
                RbacError::ExternalOpa(format!("failed to call OPA at {}: {e}", self.decision_url))
            })?;

        if !response.status().is_success() {
            let status = response.status();
            let body_text = response.text().await.unwrap_or_default();
            return Err(RbacError::ExternalOpa(format!(
                "OPA returned HTTP {status}: {body_text}"
            )));
        }

        let opa_response: OpaResponse = response
            .json()
            .await
            .map_err(|e| RbacError::ExternalOpa(format!("failed to parse OPA response: {e}")))?;

        debug!(
            "RBAC: OPA decision for user={}, op={}: allowed={}",
            input.subject.user_id, input.action.operation, opa_response.result
        );

        Ok(opa_response.result)
    }
}

impl RbacEngine for ExternalOpaEngine {
    fn evaluate(&self, input: &RbacInput) -> RbacResult<bool> {
        // Use tokio's Handle to run the async call from a sync context.
        // This is safe because we are called from within a tokio runtime.
        let handle = tokio::runtime::Handle::try_current()
            .map_err(|e| RbacError::ExternalOpa(format!("no tokio runtime available: {e}")))?;

        // Use block_in_place to avoid blocking a worker thread when called
        // from an actix-web handler (which runs on a tokio runtime).
        tokio::task::block_in_place(|| handle.block_on(self.evaluate_async(input))).inspect_err(
            |e| {
                warn!("RBAC: external OPA evaluation failed: {e}");
            },
        )
    }
}
