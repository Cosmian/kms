use std::path::PathBuf;

use clap::Parser;
use cosmian_kms_client::KmsClient;

use crate::{
    actions::{console, labels::CERTIFICATE_ID},
    error::result::KmsCliResult,
};

/// Generate a Certificate Revocation List (CRL) for a CA certificate.
///
/// The CRL is signed by the CA private key and contains all certificates
/// issued by this CA that have been revoked in the KMS.
///
/// The output format can be DER (default, RFC 2585) or PEM.
#[derive(Parser, Default, Debug)]
#[clap(verbatim_doc_comment)]
pub struct GenerateCrlAction {
    /// The unique identifier of the issuer (CA) certificate.
    #[clap(long = CERTIFICATE_ID, short = 'c', required = true)]
    pub(crate) issuer_certificate_id: String,

    /// CRL validity period in days (default: 7).
    #[clap(long = "validity-days", short = 'd', default_value = "7")]
    pub(crate) validity_days: u32,

    /// The output file path for the generated CRL.
    #[clap(long = "output-file", short = 'o', required = true)]
    pub(crate) output_file: PathBuf,

    /// Output format: `der` (default) or `pem`.
    #[clap(long = "output-format", short = 'f', default_value = "der")]
    pub(crate) output_format: String,
}

impl GenerateCrlAction {
    /// Generate the CRL by calling the REST endpoint.
    pub async fn run(&self, kms_rest_client: KmsClient) -> KmsCliResult<()> {
        let format = match self.output_format.to_lowercase().as_str() {
            "der" | "pem" => self.output_format.to_lowercase(),
            other => {
                return Err(crate::error::KmsCliError::Default(format!(
                    "Invalid output format: {other}. Supported values are: der, pem"
                )));
            }
        };

        let endpoint = format!("/certificates/{}/crl", self.issuer_certificate_id);

        let validity_days_str = self.validity_days.to_string();
        let query_params = vec![
            ("format", format.as_str()),
            ("validity_days", validity_days_str.as_str()),
        ];

        let bytes: Vec<u8> = kms_rest_client
            .get_bytes(&endpoint, Some(&query_params))
            .await?;

        std::fs::write(&self.output_file, &bytes)?;

        let stdout = console::Stdout::new(&format!(
            "CRL successfully generated and saved to {} ({} format, {} bytes)",
            self.output_file.display(),
            format,
            bytes.len()
        ));
        stdout.write()?;

        Ok(())
    }
}
