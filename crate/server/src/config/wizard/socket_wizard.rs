//! KMIP socket server configuration step of the KMS configuration wizard.

use std::io::Write as _;

use dialoguer::{Confirm, Input, theme::ColorfulTheme};

use super::PromptResultExt;
use crate::{config::SocketServerConfig, result::KResult};

pub(crate) fn configure_socket_server(
    has_clients_ca: bool,
    listen_on_all: bool,
) -> KResult<SocketServerConfig> {
    let theme = ColorfulTheme::default();

    let enable: bool = Confirm::with_theme(&theme)
        .with_prompt("Enable the KMIP socket server (TLS-based KMIP protocol)?")
        .default(false)
        .interact()
        .prompt_err()?;

    if !enable {
        return Ok(SocketServerConfig::default());
    }

    if !has_clients_ca {
        writeln!(
            std::io::stdout().lock(),
            "  ⚠  Warning: the KMIP socket server requires a client CA certificate \
             (--clients-ca-cert-file) configured in the TLS section. \
             Make sure to set it before starting the server."
        )?;
    }

    // Several nodes sit behind a load balancer or share a virtual IP: they must accept
    // connections on every interface (Windows otherwise defaults to loopback).
    let default_hostname = if listen_on_all || !cfg!(target_os = "windows") {
        "0.0.0.0"
    } else {
        "127.0.0.1"
    }
    .to_owned();

    let port: u16 = Input::with_theme(&theme)
        .with_prompt("KMIP socket server port")
        .default(5696_u16)
        .interact_text()
        .prompt_err()?;

    let hostname: String = Input::with_theme(&theme)
        .with_prompt("KMIP socket server hostname")
        .default(default_hostname)
        .interact_text()
        .prompt_err()?;

    Ok(SocketServerConfig {
        start: true,
        port,
        hostname,
    })
}
