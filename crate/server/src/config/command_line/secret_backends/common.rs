//! Shared helper functions for all secret backends.

use crate::{error::KmsError, result::KResult};

/// Run an async future on a dedicated thread with a fresh single-threaded
/// tokio runtime. Required because config loading runs before the main runtime.
pub(super) fn resolve_async<F>(future: F) -> KResult<String>
where
    F: std::future::Future<Output = KResult<String>> + Send + 'static,
{
    std::thread::spawn(move || {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| KmsError::ServerError(format!("tokio runtime: {e}")))?
            .block_on(future)
    })
    .join()
    .map_err(|e| KmsError::ServerError(format!("Secret resolution thread panicked: {e:?}")))?
}

/// Strip the `secret://` prefix and split at the first `/`.
/// Returns `(first_segment, remainder)`.
pub(super) fn parse_uri<'a>(
    uri: &'a str,
    backend_name: &str,
    format_hint: &str,
) -> KResult<(&'a str, &'a str)> {
    let rest = uri
        .strip_prefix("secret://")
        .ok_or_else(|| KmsError::InvalidRequest(format!("Invalid secret URI: {uri}")))?;
    let slash = rest.find('/').ok_or_else(|| {
        KmsError::InvalidRequest(format!(
            "{backend_name} URI must be {format_hint}, got: {uri}"
        ))
    })?;
    Ok((&rest[..slash], &rest[slash + 1..]))
}

/// Check that a required credential is non-empty.
pub(super) fn require_non_empty(value: &str, name: &str, backend: &str) -> KResult<()> {
    if value.is_empty() {
        return Err(KmsError::ServerError(format!(
            "{name} is not set; required for {backend} secret backend"
        )));
    }
    Ok(())
}

/// Send an HTTP request and return the parsed JSON body,
/// or a descriptive error including the URI and backend name.
pub(super) async fn http_json(
    req: reqwest::RequestBuilder,
    uri: &str,
    backend: &str,
) -> KResult<serde_json::Value> {
    let resp = req
        .send()
        .await
        .map_err(|e| KmsError::ServerError(format!("{backend} request failed for {uri}: {e}")))?;
    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(KmsError::ServerError(format!(
            "{backend} returned HTTP {status} for {uri}: {body}"
        )));
    }
    resp.json().await.map_err(|e| {
        KmsError::ServerError(format!("{backend} response parse error for {uri}: {e}"))
    })
}
