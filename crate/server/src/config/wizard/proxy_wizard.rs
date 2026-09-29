//! Proxy configuration step of the KMS configuration wizard.

#![allow(unreachable_pub)]

use dialoguer::{Confirm, Input, theme::ColorfulTheme};

use crate::{config::ProxyConfig, error::KmsError, result::KResult};

pub fn configure_proxy() -> KResult<ProxyConfig> {
    let theme = ColorfulTheme::default();

    let enable: bool = Confirm::with_theme(&theme)
        .with_prompt("Configure an outbound proxy?")
        .default(false)
        .interact()
        .map_err(|e| KmsError::ServerError(format!("Prompt error: {e}")))?;

    if !enable {
        return Ok(ProxyConfig::default());
    }

    let proxy_url: String = Input::with_theme(&theme)
        .with_prompt("Proxy URL (e.g. https://proxy.example.com or socks5://192.168.1.1:9000)")
        .interact_text()
        .map_err(|e| KmsError::ServerError(format!("Prompt error: {e}")))?;

    let proxy_basic_auth_username: String = Input::with_theme(&theme)
        .with_prompt("Proxy Basic-Auth username (leave blank to skip)")
        .allow_empty(true)
        .interact_text()
        .map_err(|e| KmsError::ServerError(format!("Prompt error: {e}")))?;

    let proxy_basic_auth_password: Option<String> = if proxy_basic_auth_username.trim().is_empty() {
        None
    } else {
        let pwd: String = dialoguer::Password::with_theme(&theme)
            .with_prompt("Proxy Basic-Auth password")
            .interact()
            .map_err(|e| KmsError::ServerError(format!("Prompt error: {e}")))?;
        Some(pwd)
    };

    let proxy_custom_auth_header: String = Input::with_theme(&theme)
        .with_prompt("Custom Proxy-Authorization header value (leave blank to skip)")
        .allow_empty(true)
        .interact_text()
        .map_err(|e| KmsError::ServerError(format!("Prompt error: {e}")))?;

    let proxy_exclusion_list_str: String = Input::with_theme(&theme)
        .with_prompt("No-proxy exclusion list (comma-separated hosts; leave blank to skip)")
        .allow_empty(true)
        .interact_text()
        .map_err(|e| KmsError::ServerError(format!("Prompt error: {e}")))?;
    let proxy_exclusion_list: Option<Vec<String>> = if proxy_exclusion_list_str.trim().is_empty() {
        None
    } else {
        Some(
            proxy_exclusion_list_str
                .split(',')
                .map(|s| s.trim().to_owned())
                .filter(|s| !s.is_empty())
                .collect(),
        )
    };

    Ok(ProxyConfig {
        proxy_url: Some(proxy_url),
        proxy_basic_auth_username: if proxy_basic_auth_username.trim().is_empty() {
            None
        } else {
            Some(proxy_basic_auth_username)
        },
        proxy_basic_auth_password,
        proxy_custom_auth_header: if proxy_custom_auth_header.trim().is_empty() {
            None
        } else {
            Some(proxy_custom_auth_header)
        },
        proxy_exclusion_list,
    })
}
