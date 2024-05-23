use clap::Parser;
use cosmian_kms_client::KmsClient;

use crate::{actions::shared::utils::validate, error::CliError};

/// Validate a certificate.
///
/// A certificate or a chain of certificates is validated.
/// It means that the certificate chain is valid in terms of time, well signed,
/// complete, and no components has been flagged as removed.
#[derive(Parser, Debug)]
pub struct ValidateCertificatesAction {
    /// One or more Certificates.
    #[clap(long = "certificate", short = 'v', group = "certificate-tags")]
    pub certificate: Vec<String>,
    /// One or more Unique Identifiers of Certificate Objects.
    #[clap(long = "unique-identifier", short = 'k', group = "certificate-tags")]
    pub unique_identifier: Vec<String>,
    /// A Date-Time object indicating when the certificate chain needs to be
    /// valid. If omitted, the current date and time SHALL be assumed.
    #[clap(
        long = "validity-time",
        short = 't',
        value_name = "DATE",
        group = "certificate-tags"
    )]
    pub validity_time: String,
}

impl ValidateCertificatesAction {
    pub async fn run(&self, client_connector: &KmsClient) -> Result<(), CliError> {
        validate(
            client_connector,
            self.certificate.clone(),
            self.unique_identifier.clone(),
            self.validity_time.clone(),
        )
        .await
    }
}
