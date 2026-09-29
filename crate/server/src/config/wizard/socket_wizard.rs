//! KMIP socket server configuration step of the KMS configuration wizard.

#![allow(unreachable_pub, clippy::print_stdout)]

use dialoguer::{Confirm, Input, theme::ColorfulTheme};

use crate::{config::SocketServerConfig, error::KmsError, result::KResult};

pub fn configure_socket_server(has_clients_ca: bool) -> KResult<SocketServerConfig> {
    let theme = ColorfulTheme::default();

    let enable: bool = Confirm::with_theme(&theme)
        .with_prompt("Enable the KMIP socket server (TLS-based KMIP protocol)?")
        .default(false)
        .interact()
        .map_err(|e| KmsError::ServerError(format!("Prompt error: {e}")))?;

    if !enable {
        return Ok(SocketServerConfig::default());
    }

    if !has_clients_ca {
        println!(
            "  ⚠  Warning: the KMIP socket server requires a client CA certificate \
             (--clients-ca-cert-file) configured in the TLS section. \
             Make sure to set it before starting the server."
        );
    }

    #[cfg(target_os = "windows")]
    let default_hostname = "127.0.0.1".to_owned();
    #[cfg(not(target_os = "windows"))]
    let default_hostname = "0.0.0.0".to_owned();

    let port: u16 = Input::with_theme(&theme)
        .with_prompt("KMIP socket server port")
        .default(5696_u16)
        .interact_text()
        .map_err(|e| KmsError::ServerError(format!("Prompt error: {e}")))?;

    let hostname: String = Input::with_theme(&theme)
        .with_prompt("KMIP socket server hostname")
        .default(default_hostname)
        .interact_text()
        .map_err(|e| KmsError::ServerError(format!("Prompt error: {e}")))?;

    Ok(SocketServerConfig {
        socket_server_start: true,
        socket_server_port: port,
        socket_server_hostname: hostname,
    })
}
