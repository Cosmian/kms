//! HTTP server configuration step of the KMS configuration wizard.

#![allow(unreachable_pub)]

use dialoguer::{Input, theme::ColorfulTheme};

use crate::{config::HttpConfig, error::KmsError, result::KResult};

/// Build the default CORS allowed-origins list for `port` and `scheme`.
///
/// Includes `localhost`, `127.0.0.1`, `0.0.0.0`, `[::1]`, and `[::]` so that
/// the bundled Web UI works out-of-the-box from any loopback address (mirrors
/// the Docker image defaults in `nix/docker.nix`).
pub(super) fn default_cors_origins(scheme: &str, port: u16) -> Vec<String> {
    let hosts = ["localhost", "127.0.0.1", "0.0.0.0", "[::1]", "[::]"];
    hosts
        .iter()
        .map(|h| format!("{scheme}://{h}:{port}"))
        .collect()
}

pub fn configure_http() -> KResult<HttpConfig> {
    let theme = ColorfulTheme::default();

    #[cfg(target_os = "windows")]
    let default_hostname = "127.0.0.1".to_owned();
    #[cfg(not(target_os = "windows"))]
    let default_hostname = "0.0.0.0".to_owned();

    let port: u16 = Input::with_theme(&theme)
        .with_prompt("HTTP server port")
        .default(9998_u16)
        .interact_text()
        .map_err(|e| KmsError::ServerError(format!("Prompt error: {e}")))?;

    let hostname: String = Input::with_theme(&theme)
        .with_prompt("HTTP server hostname")
        .default(default_hostname)
        .interact_text()
        .map_err(|e| KmsError::ServerError(format!("Prompt error: {e}")))?;

    let rate_limit_str: String = Input::with_theme(&theme)
        .with_prompt("Rate limit (max requests/second per IP; leave blank to disable)")
        .allow_empty(true)
        .interact_text()
        .map_err(|e| KmsError::ServerError(format!("Prompt error: {e}")))?;
    let rate_limit_per_second: Option<u32> = if rate_limit_str.trim().is_empty() {
        None
    } else {
        rate_limit_str.trim().parse().ok()
    };

    // CORS origins are populated later in the wizard (after TLS and public-URL
    // are known). Pre-fill with an empty list so the field is present in the
    // config struct; `mod.rs` will replace this with the computed value.
    Ok(HttpConfig {
        port,
        hostname,
        api_token_id: None,
        rate_limit_per_second,
        cors_allowed_origins: None,
    })
}
