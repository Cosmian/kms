mod cacerts;
mod enroll;

use base64::{Engine as _, engine::general_purpose::STANDARD};
pub use cacerts::EstCaCertsAction;
use clap::Subcommand;
use cosmian_kms_client::KmsClient;
pub use enroll::EstEnrollAction;
use openssl::pkcs7::Pkcs7;

use crate::error::{KmsCliError, result::KmsCliResult};

/// Interact with the KMS EST (RFC 7030) enrollment endpoints as a client: download the CA
/// certificate chain and enroll a device certificate from a PKCS#10 CSR.
#[derive(Subcommand)]
pub enum EstCommands {
    /// Download the CA certificate chain (public endpoint).
    #[command(name = "cacerts")]
    CaCerts(EstCaCertsAction),
    Enroll(EstEnrollAction),
}

impl EstCommands {
    /// Run the selected EST subcommand.
    ///
    /// # Errors
    /// Returns an error if the request to the EST endpoint fails or its response is invalid.
    pub async fn process(&self, kms_rest_client: KmsClient) -> KmsCliResult<()> {
        match self {
            Self::CaCerts(action) => action.run(kms_rest_client).await,
            Self::Enroll(action) => action.run(kms_rest_client).await,
        }
    }
}

/// Decode an EST response body (base64 text, RFC 7030 §4.1.3 `Content-Transfer-Encoding:
/// base64`) carrying a degenerate PKCS#7 `SignedData`, and re-encode every certificate it
/// contains as concatenated `-----BEGIN CERTIFICATE-----` PEM — the format directly usable
/// by `openssl x509`, trust stores, and TLS server configs.
pub(super) fn pkcs7_body_to_pem(body_base64: &str) -> KmsCliResult<Vec<u8>> {
    // The body may be line-wrapped base64: drop all ASCII whitespace before decoding.
    let compact: String = body_base64
        .chars()
        .filter(|c| !c.is_ascii_whitespace())
        .collect();
    let der = STANDARD.decode(compact)?;
    let p7 = Pkcs7::from_der(&der)
        .map_err(|e| KmsCliError::Default(format!("invalid PKCS#7 EST response: {e}")))?;
    let certs = p7
        .signed()
        .and_then(|signed| signed.certificates())
        .ok_or_else(|| {
            KmsCliError::Default("the EST response carries no certificate".to_owned())
        })?;
    let mut pem = Vec::new();
    for cert in certs {
        pem.extend(cert.to_pem().map_err(KmsCliError::from)?);
    }
    Ok(pem)
}
