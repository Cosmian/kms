use std::path::PathBuf;

use clap::Parser;
use cosmian_kms_client::{KmsClient, read_bytes_from_file, write_bytes_to_file};
use openssl::x509::X509Req;

use super::pkcs7_body_to_pem;
use crate::{
    actions::console,
    error::{KmsCliError, result::KmsCliResult},
};

/// Enroll a device certificate from a PKCS#10 CSR via the KMS EST (RFC 7030)
/// `/.well-known/est/simpleenroll` endpoint.
///
/// Authentication is either a TLS client certificate — configured via
/// `tls_client_pem_cert_path`/`tls_client_pem_key_path` or `tls_client_pkcs12_path` in the
/// ckms configuration — or HTTP Basic bootstrap credentials (`--user`/`--password`), only
/// accepted when the server has `est_require_client_cert = false`.
#[derive(Parser)]
pub struct EstEnrollAction {
    /// Path to the PKCS#10 certificate signing request to submit.
    #[clap(long = "csr", short = 'r')]
    pub(crate) csr: PathBuf,

    /// The format of the certificate signing request.
    #[clap(long = "csr-format", short = 'f', default_value = "pem", value_parser(["pem", "der"]))]
    pub(crate) csr_format: String,

    /// The file to write the issued certificate to (PEM).
    #[clap(long = "out", short = 'o')]
    pub(crate) out: PathBuf,

    /// Username for HTTP Basic bootstrap authentication. Requires `--password`.
    #[clap(long = "user", requires = "password")]
    pub(crate) user: Option<String>,

    /// Password for HTTP Basic bootstrap authentication. Requires `--user`.
    #[clap(long = "password", requires = "user")]
    pub(crate) password: Option<String>,
}

impl EstEnrollAction {
    /// Submit the CSR and write the issued certificate as PEM.
    ///
    /// # Errors
    /// Returns an error if the CSR is invalid, the request fails, the server rejects it, or the
    /// response is invalid.
    pub async fn run(&self, kms_rest_client: KmsClient) -> KmsCliResult<()> {
        let csr_bytes = read_bytes_from_file(&self.csr)?;
        let csr = if self.csr_format == "der" {
            X509Req::from_der(&csr_bytes)
        } else {
            X509Req::from_pem(&csr_bytes)
        }
        .map_err(|e| KmsCliError::InvalidRequest(format!("invalid CSR: {e}")))?;
        let der = csr.to_der().map_err(KmsCliError::from)?;

        let url = format!(
            "{}/.well-known/est/simpleenroll",
            kms_rest_client.client.server_url
        );
        let response = match (&self.user, &self.password) {
            (Some(user), Some(password)) => {
                kms_rest_client
                    .client
                    .post_bytes_with_basic_auth(&url, der, "application/pkcs10", user, password)
                    .await?
            }
            _ => {
                kms_rest_client
                    .client
                    .post_bytes(&url, der, "application/pkcs10")
                    .await?
            }
        };
        if !response.status.is_success() {
            return Err(KmsCliError::ServerError(format!(
                "POST /.well-known/est/simpleenroll failed: HTTP {} - {}",
                response.status,
                response.text().unwrap_or_default()
            )));
        }
        let pem = pkcs7_body_to_pem(&response.text()?)?;
        write_bytes_to_file(&pem, &self.out)?;
        console::Stdout::new(&format!(
            "The certificate was successfully issued and written to {}",
            self.out.display()
        ))
        .write()?;
        Ok(())
    }
}
