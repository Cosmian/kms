use std::path::PathBuf;

use clap::Parser;
use cosmian_kms_client::{KmsClient, write_bytes_to_file};

use super::pkcs7_body_to_pem;
use crate::{
    actions::console,
    error::{KmsCliError, result::KmsCliResult},
};

/// Download the CA certificate chain from the KMS EST (RFC 7030) endpoint.
///
/// `GET /.well-known/est/cacerts` is public (no authentication). The response is a
/// degenerate PKCS#7 `SignedData`; this command decodes it and writes the chain as
/// concatenated PEM certificates.
#[derive(Parser)]
pub struct EstCaCertsAction {
    /// The file to write the CA certificate chain to (PEM).
    #[clap(long = "out", short = 'o')]
    pub(crate) out: PathBuf,
}

impl EstCaCertsAction {
    /// Download the CA chain and write it as PEM.
    ///
    /// # Errors
    /// Returns an error if the request fails, the server rejects it, or the response is invalid.
    pub async fn run(&self, kms_rest_client: KmsClient) -> KmsCliResult<()> {
        let url = format!(
            "{}/.well-known/est/cacerts",
            kms_rest_client.client.server_url
        );
        let response = kms_rest_client.client.get(&url).await?;
        if !response.status.is_success() {
            return Err(KmsCliError::ServerError(format!(
                "GET /.well-known/est/cacerts failed: HTTP {} - {}",
                response.status,
                response.text().unwrap_or_default()
            )));
        }
        let pem = pkcs7_body_to_pem(&response.text()?)?;
        write_bytes_to_file(&pem, &self.out)?;
        console::Stdout::new(&format!(
            "The CA certificate chain was written to {}",
            self.out.display()
        ))
        .write()?;
        Ok(())
    }
}
