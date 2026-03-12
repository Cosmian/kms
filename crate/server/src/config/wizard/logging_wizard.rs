//! Logging configuration step of the KMS configuration wizard.

#![allow(unreachable_pub)]

use std::path::PathBuf;

use dialoguer::{Confirm, Input, theme::ColorfulTheme};

use crate::{config::LoggingConfig, error::KmsError, result::KResult};

pub fn configure_logging() -> KResult<LoggingConfig> {
    let theme = ColorfulTheme::default();

    let rust_log: String = Input::with_theme(&theme)
        .with_prompt(
            "Log filter (RUST_LOG format, e.g. 'info,cosmian_kms_server=debug'; \
             leave blank for default)",
        )
        .allow_empty(true)
        .interact_text()
        .map_err(|e| KmsError::ServerError(format!("Prompt error: {e}")))?;

    let otlp: String = Input::with_theme(&theme)
        .with_prompt("OpenTelemetry OTLP collector URL (leave blank to disable)")
        .allow_empty(true)
        .interact_text()
        .map_err(|e| KmsError::ServerError(format!("Prompt error: {e}")))?;

    let quiet: bool = Confirm::with_theme(&theme)
        .with_prompt("Suppress stdout logs (quiet mode)?")
        .default(false)
        .interact()
        .map_err(|e| KmsError::ServerError(format!("Prompt error: {e}")))?;

    #[cfg(not(target_os = "windows"))]
    let log_to_syslog: bool = Confirm::with_theme(&theme)
        .with_prompt("Write logs to syslog?")
        .default(false)
        .interact()
        .map_err(|e| KmsError::ServerError(format!("Prompt error: {e}")))?;

    let rolling_log: bool = Confirm::with_theme(&theme)
        .with_prompt("Enable rolling daily log files?")
        .default(false)
        .interact()
        .map_err(|e| KmsError::ServerError(format!("Prompt error: {e}")))?;

    let (rolling_log_dir, rolling_log_name) = if rolling_log {
        #[cfg(not(target_os = "windows"))]
        let default_log_dir = "/var/log".to_owned();
        #[cfg(target_os = "windows")]
        let default_log_dir = std::env::var("LOCALAPPDATA").map_or_else(
            |_| String::from("C:\\ProgramData\\cosmian\\logs"),
            |localappdata| format!("{localappdata}\\Cosmian KMS Server\\logs"),
        );

        let dir: String = Input::with_theme(&theme)
            .with_prompt("Rolling log directory path")
            .default(default_log_dir)
            .interact_text()
            .map_err(|e| KmsError::ServerError(format!("Prompt error: {e}")))?;
        let name: String = Input::with_theme(&theme)
            .with_prompt("Rolling log file name prefix (default: 'kms')")
            .default("kms".to_owned())
            .interact_text()
            .map_err(|e| KmsError::ServerError(format!("Prompt error: {e}")))?;
        (Some(PathBuf::from(dir)), Some(name))
    } else {
        (None, None)
    };

    let enable_metering: bool = Confirm::with_theme(&theme)
        .with_prompt("Enable telemetry metering (in addition to tracing)?")
        .default(false)
        .interact()
        .map_err(|e| KmsError::ServerError(format!("Prompt error: {e}")))?;

    let environment: String = Input::with_theme(&theme)
        .with_prompt("Environment name (e.g. development, staging, production)")
        .default("development".to_owned())
        .interact_text()
        .map_err(|e| KmsError::ServerError(format!("Prompt error: {e}")))?;

    let ansi_colors: bool = Confirm::with_theme(&theme)
        .with_prompt("Enable ANSI colors in stdout logs?")
        .default(false)
        .interact()
        .map_err(|e| KmsError::ServerError(format!("Prompt error: {e}")))?;

    Ok(LoggingConfig {
        rust_log: if rust_log.trim().is_empty() {
            None
        } else {
            Some(rust_log)
        },
        otlp: if otlp.trim().is_empty() {
            None
        } else {
            Some(otlp)
        },
        quiet,
        #[cfg(not(target_os = "windows"))]
        log_to_syslog,
        rolling_log_dir,
        rolling_log_name,
        enable_metering,
        environment: Some(environment),
        ansi_colors,
    })
}
