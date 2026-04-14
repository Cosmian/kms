//! HTTP server configuration step of the KMS configuration wizard.

#![allow(unreachable_pub)]

use dialoguer::{Input, theme::ColorfulTheme};

use crate::{config::HttpConfig, error::KmsError, result::KResult};

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

    Ok(HttpConfig {
        port,
        hostname,
        api_token_id: None,
        rate_limit_per_second: None,
        cors_allowed_origins: None,
    })
}
