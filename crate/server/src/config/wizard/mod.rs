//! Interactive configuration wizard for the Cosmian KMS server.
//!
//! Invoked via `cosmian_kms configure`.  Walks the user through every
//! configuration section in sequence and writes the result to the
//! platform-specific default configuration path.
//!
//! The wizard covers:
//! 1. Database
//! 2. HTTP server
//! 3. TLS / certificates  (optionally generates a self-signed PKI)
//! 4. KMIP socket server
//! 5. Authentication (API key, JWT/OIDC, client certificates)
//! 6. HSM
//! 7. Logging
//! 8. Proxy
//! 9. Advanced (workspace, key management, MS DKE, KMIP policy, Google CSE,
//!    Azure EKM, AWS XKS, UI)

#![allow(clippy::print_stdout)]

mod advanced_wizard;
mod auth_wizard;
mod cert_gen;
mod db_wizard;
mod hsm_wizard;
mod http_wizard;
mod logging_wizard;
mod proxy_wizard;
mod socket_wizard;
#[cfg(test)]
mod tests;
mod tls_wizard;

use dialoguer::{Input, theme::ColorfulTheme};

use crate::{
    config::{ClapConfig, UiConfig, get_default_config_path},
    error::KmsError,
    result::KResult,
};

/// Run the interactive configuration wizard and write the configuration file.
///
/// # Errors
/// Returns an error if any prompt fails, certificate generation fails, or the
/// resulting TOML cannot be serialized / written to disk.
pub fn run_configure_wizard() -> KResult<()> {
    let output_path = get_default_config_path();

    // Handle --help / -h early
    let args: Vec<String> = std::env::args().collect();
    if args.iter().any(|a| a == "--help" || a == "-h") {
        println!(
            "cosmian_kms configure\n\n\
             Interactive configuration wizard for the Cosmian KMS server.\n\n\
             USAGE:\n    cosmian_kms configure [OPTIONS]\n\n\
             OPTIONS:\n    -h, --help    Print this help message\n\n\
             The wizard guides you through all server configuration options and\n\
             writes the result to {output_path}.\n"
        );
        return Ok(());
    }

    println!();
    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║         Cosmian KMS — Interactive Configuration Wizard       ║");
    println!("╚══════════════════════════════════════════════════════════════╝");
    println!();
    println!("This wizard will guide you through all server configuration options.");
    println!("The resulting configuration will be written to: {output_path}");
    println!();

    // ── [1/9] Database ────────────────────────────────────────────────────────
    println!("[1/9] Database configuration");
    println!("──────────────────────────────");
    let db = db_wizard::configure_db()?;
    println!();

    // ── [2/9] HTTP server ─────────────────────────────────────────────────────
    println!("[2/9] HTTP server configuration");
    println!("──────────────────────────────");
    let mut http = http_wizard::configure_http()?;
    println!();

    // ── [3/9] TLS / certificates ──────────────────────────────────────────────
    println!("[3/9] TLS / Certificate configuration");
    println!("──────────────────────────────────────");
    let tls_result = tls_wizard::configure_tls()?;
    let mut tls = tls_result.tls;
    let has_clients_ca = tls.clients_ca_cert_file.is_some();
    // Build default CORS origins now that TLS is known (determines scheme).
    let scheme = http.scheme(&tls);
    http.cors_allowed_origins = Some(http_wizard::default_cors_origins(scheme, http.port));
    println!();

    // ── [4/9] KMIP socket server ──────────────────────────────────────────────
    println!("[4/9] KMIP socket server configuration");
    println!("───────────────────────────────────────");
    let socket_server = socket_wizard::configure_socket_server(has_clients_ca)?;

    // The KMIP socket server authenticates clients exclusively via mTLS.
    // If it was just enabled but `clients_ca_cert_file` is not set, fix that now.
    if socket_server.socket_server_start && tls.clients_ca_cert_file.is_none() {
        if let Some(ca_cert) = tls_result.generated_ca_cert {
            println!("  ℹ  KMIP socket server requires mTLS — enabling it automatically.");
            println!("     clients_ca_cert_file = {}", ca_cert.display());
            tls.clients_ca_cert_file = Some(ca_cert);
        } else {
            println!("  ⚠  The KMIP socket server requires mutual TLS (mTLS).");
            println!(
                "     Please provide the CA certificate that will be used to validate client certificates."
            );
            let ca: String = Input::with_theme(&ColorfulTheme::default())
                .with_prompt("Clients CA certificate file path (--clients-ca-cert-file)")
                .interact_text()
                .map_err(|e| KmsError::ServerError(format!("Prompt error: {e}")))?;
            tls.clients_ca_cert_file = Some(std::path::PathBuf::from(ca));
        }
    }
    println!();

    // ── [5/9] Authentication ──────────────────────────────────────────────────
    println!("[5/9] Authentication configuration");
    println!("───────────────────────────────────");
    let mut ui_config = UiConfig::default();
    let auth_result = auth_wizard::configure_auth(&mut http, &mut ui_config)?;
    println!();

    // ── [6/9] HSM ─────────────────────────────────────────────────────────────
    println!("[6/9] Hardware Security Module (HSM) configuration");
    println!("───────────────────────────────────────────────────");
    let hsm = hsm_wizard::configure_hsm()?;
    println!();

    // ── [7/9] Logging ─────────────────────────────────────────────────────────
    println!("[7/9] Logging configuration");
    println!("────────────────────────────");
    let logging = logging_wizard::configure_logging()?;
    println!();

    // ── [8/9] Proxy ───────────────────────────────────────────────────────────
    println!("[8/9] Proxy configuration");
    println!("──────────────────────────");
    let proxy = proxy_wizard::configure_proxy()?;
    println!();

    // ── [9/9] Advanced ────────────────────────────────────────────────────────
    println!("[9/9] Advanced / miscellaneous configuration");
    println!("─────────────────────────────────────────────");
    let advanced = advanced_wizard::configure_advanced(ui_config)?;
    println!();

    // Prepend kms_public_url to CORS origins if it was set and is not already present.
    if let Some(ref public_url) = advanced.kms_public_url {
        let origins = http.cors_allowed_origins.get_or_insert_with(Vec::new);
        if !origins.iter().any(|o| o == public_url) {
            origins.insert(0, public_url.clone());
        }
    }

    // Assemble the final ClapConfig using struct-update syntax so that any
    // field added to ClapConfig in the future is automatically included with
    // its default value, keeping the wizard in sync without requiring changes
    // here.
    let config = ClapConfig {
        db,
        http,
        tls,
        socket_server,
        idp_auth: auth_result.idp_auth,
        ui_config: advanced.ui_config,
        hsm,
        logging,
        proxy,
        workspace: advanced.workspace,
        vendor_identification: advanced.vendor_identification,
        key_encryption_key: advanced.key_encryption_key,
        default_unwrap_type: advanced.default_unwrap_type,
        privileged_users: advanced.privileged_users,
        ms_dke_service_url: advanced.ms_dke_service_url,
        kms_public_url: advanced.kms_public_url,
        kmip_policy: advanced.kmip_policy,
        google_cse_config: advanced.google_cse_config,
        azure_ekm_config: advanced.azure_ekm_config,
        aws_xks_config: advanced.aws_xks_config,
        default_username: auth_result.default_username,
        force_default_username: auth_result.force_default_username,
        ..ClapConfig::default()
    };

    // Serialize to TOML
    let toml_content = toml::to_string_pretty(&config)
        .map_err(|e| KmsError::ServerError(format!("Failed to serialize configuration: {e}")))?;

    // Write to output path (create parent directory if needed)
    let output_file = std::path::Path::new(&output_path);
    if let Some(parent) = output_file.parent() {
        std::fs::create_dir_all(parent).map_err(|e| {
            KmsError::ServerError(format!("Cannot create directory {}: {e}", parent.display()))
        })?;
    }
    std::fs::write(output_file, &toml_content)
        .map_err(|e| KmsError::ServerError(format!("Cannot write {output_path}: {e}")))?;

    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║                  Configuration complete!                     ║");
    println!("╚══════════════════════════════════════════════════════════════╝");
    println!();
    println!("Configuration written to: {output_path}");
    println!();

    if let Some(client_cert) = tls_result.generated_client_cert {
        println!(
            "  Self-signed client certificate: {}",
            client_cert.display()
        );
        println!("  Distribute this certificate to clients that need to authenticate via mTLS.\n");
    }

    println!("Start the server with:");
    println!("  cosmian_kms -c {output_path}");
    println!();

    Ok(())
}
