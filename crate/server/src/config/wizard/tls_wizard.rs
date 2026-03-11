//! TLS configuration step of the KMS configuration wizard.
//!
//! Optionally generates a self-signed PKI or accepts manual PEM paths.

#![allow(unreachable_pub, clippy::print_stdout)]

use std::path::PathBuf;

use dialoguer::{Confirm, Input, theme::ColorfulTheme};

use super::cert_gen::{CertGenOptions, generate_self_signed_pki};
use crate::{config::TlsConfig, error::KmsError, result::KResult};

pub struct TlsWizardResult {
    pub tls: TlsConfig,
    /// Populated when self-signed certs were generated; clients need the CA
    /// cert to authenticate the server.
    pub generated_client_cert: Option<PathBuf>,
}

pub fn configure_tls() -> KResult<TlsWizardResult> {
    let theme = ColorfulTheme::default();

    let enable_tls: bool = Confirm::with_theme(&theme)
        .with_prompt("Enable TLS?")
        .default(true)
        .interact()
        .map_err(|e| KmsError::ServerError(format!("Prompt error: {e}")))?;

    if !enable_tls {
        return Ok(TlsWizardResult {
            tls: TlsConfig::default(),
            generated_client_cert: None,
        });
    }

    let generate_certs: bool = Confirm::with_theme(&theme)
        .with_prompt(
            "Generate self-signed certificates (CA → server + client)? \
             (Answer 'no' to provide your own paths)",
        )
        .default(true)
        .interact()
        .map_err(|e| KmsError::ServerError(format!("Prompt error: {e}")))?;

    if generate_certs {
        let certs_dir: String = Input::with_theme(&theme)
            .with_prompt("Directory to write certificate files")
            .default("/etc/cosmian".to_owned())
            .interact_text()
            .map_err(|e| KmsError::ServerError(format!("Prompt error: {e}")))?;

        let ca_cn: String = Input::with_theme(&theme)
            .with_prompt("CA Common Name (CN)")
            .default("Cosmian KMS CA".to_owned())
            .interact_text()
            .map_err(|e| KmsError::ServerError(format!("Prompt error: {e}")))?;

        let server_cn: String = Input::with_theme(&theme)
            .with_prompt("Server certificate Common Name (CN)")
            .default("Cosmian KMS Server".to_owned())
            .interact_text()
            .map_err(|e| KmsError::ServerError(format!("Prompt error: {e}")))?;

        let client_cn: String = Input::with_theme(&theme)
            .with_prompt("Client certificate Common Name (CN)")
            .default("Cosmian KMS Client".to_owned())
            .interact_text()
            .map_err(|e| KmsError::ServerError(format!("Prompt error: {e}")))?;

        let ca_validity_days: u32 = Input::with_theme(&theme)
            .with_prompt("CA certificate validity (days)")
            .default(3650_u32)
            .interact_text()
            .map_err(|e| KmsError::ServerError(format!("Prompt error: {e}")))?;

        let server_validity_days: u32 = Input::with_theme(&theme)
            .with_prompt("Server certificate validity (days)")
            .default(365_u32)
            .interact_text()
            .map_err(|e| KmsError::ServerError(format!("Prompt error: {e}")))?;

        let client_validity_days: u32 = Input::with_theme(&theme)
            .with_prompt("Client certificate validity (days)")
            .default(365_u32)
            .interact_text()
            .map_err(|e| KmsError::ServerError(format!("Prompt error: {e}")))?;

        let opts = CertGenOptions {
            output_dir: PathBuf::from(&certs_dir),
            ca_cn,
            server_cn,
            client_cn,
            ca_validity_days,
            server_validity_days,
            client_validity_days,
        };

        println!("  Generating self-signed PKI…");
        let paths = generate_self_signed_pki(&opts)?;

        let cipher_suites = prompt_cipher_suites(&theme)?;

        let enable_mtls: bool = Confirm::with_theme(&theme)
            .with_prompt(
                "Enable mutual TLS (mTLS)? \
                 (clients must present a certificate to authenticate)",
            )
            .default(false)
            .interact()
            .map_err(|e| KmsError::ServerError(format!("Prompt error: {e}")))?;

        return Ok(TlsWizardResult {
            tls: TlsConfig {
                tls_cert_file: Some(paths.server_cert),
                tls_key_file: Some(paths.server_key),
                tls_chain_file: None,
                clients_ca_cert_file: if enable_mtls {
                    Some(paths.ca_cert.clone())
                } else {
                    None
                },
                tls_cipher_suites: cipher_suites,
                #[cfg(feature = "non-fips")]
                tls_p12_file: None,
                #[cfg(feature = "non-fips")]
                tls_p12_password: None,
            },
            generated_client_cert: if enable_mtls {
                Some(paths.client_cert)
            } else {
                None
            },
        });
    }

    // Manual path entry
    #[cfg(feature = "non-fips")]
    {
        let use_p12: bool = Confirm::with_theme(&theme)
            .with_prompt("Use a PKCS#12 (.p12) file instead of separate PEM files?")
            .default(false)
            .interact()
            .map_err(|e| KmsError::ServerError(format!("Prompt error: {e}")))?;

        if use_p12 {
            let p12_path: String = Input::with_theme(&theme)
                .with_prompt("Path to PKCS#12 file")
                .interact_text()
                .map_err(|e| KmsError::ServerError(format!("Prompt error: {e}")))?;

            let p12_password: String = dialoguer::Password::with_theme(&theme)
                .with_prompt("PKCS#12 password")
                .interact()
                .map_err(|e| KmsError::ServerError(format!("Prompt error: {e}")))?;

            let ca_cert: String = Input::with_theme(&theme)
                .with_prompt("Clients CA certificate file (for mTLS, leave blank to skip)")
                .allow_empty(true)
                .interact_text()
                .map_err(|e| KmsError::ServerError(format!("Prompt error: {e}")))?;

            let cipher_suites = prompt_cipher_suites(&theme)?;

            return Ok(TlsWizardResult {
                tls: TlsConfig {
                    tls_p12_file: Some(PathBuf::from(p12_path)),
                    tls_p12_password: Some(p12_password),
                    tls_cert_file: None,
                    tls_key_file: None,
                    tls_chain_file: None,
                    clients_ca_cert_file: if ca_cert.trim().is_empty() {
                        None
                    } else {
                        Some(PathBuf::from(ca_cert))
                    },
                    tls_cipher_suites: cipher_suites,
                },
                generated_client_cert: None,
            });
        }
    }

    // PEM manual entry
    let cert_file: String = Input::with_theme(&theme)
        .with_prompt("Path to server certificate PEM file (--tls-cert-file)")
        .interact_text()
        .map_err(|e| KmsError::ServerError(format!("Prompt error: {e}")))?;

    let key_file: String = Input::with_theme(&theme)
        .with_prompt("Path to server private key PEM file (--tls-key-file)")
        .interact_text()
        .map_err(|e| KmsError::ServerError(format!("Prompt error: {e}")))?;

    let chain_file: String = Input::with_theme(&theme)
        .with_prompt("Path to certificate chain PEM file (optional, leave blank to skip)")
        .allow_empty(true)
        .interact_text()
        .map_err(|e| KmsError::ServerError(format!("Prompt error: {e}")))?;

    let ca_cert_file: String = Input::with_theme(&theme)
        .with_prompt("Clients CA certificate file for mTLS (optional, leave blank to skip)")
        .allow_empty(true)
        .interact_text()
        .map_err(|e| KmsError::ServerError(format!("Prompt error: {e}")))?;

    let cipher_suites = prompt_cipher_suites(&theme)?;

    Ok(TlsWizardResult {
        tls: TlsConfig {
            tls_cert_file: Some(PathBuf::from(cert_file)),
            tls_key_file: Some(PathBuf::from(key_file)),
            tls_chain_file: if chain_file.trim().is_empty() {
                None
            } else {
                Some(PathBuf::from(chain_file))
            },
            clients_ca_cert_file: if ca_cert_file.trim().is_empty() {
                None
            } else {
                Some(PathBuf::from(ca_cert_file))
            },
            tls_cipher_suites: cipher_suites,
            #[cfg(feature = "non-fips")]
            tls_p12_file: None,
            #[cfg(feature = "non-fips")]
            tls_p12_password: None,
        },
        generated_client_cert: None,
    })
}

fn prompt_cipher_suites(theme: &ColorfulTheme) -> KResult<Option<String>> {
    let cipher_suites: String = Input::with_theme(theme)
        .with_prompt("TLS cipher suites (colon-separated OpenSSL string, leave blank for defaults)")
        .allow_empty(true)
        .interact_text()
        .map_err(|e| KmsError::ServerError(format!("Prompt error: {e}")))?;
    Ok(if cipher_suites.trim().is_empty() {
        None
    } else {
        Some(cipher_suites)
    })
}
