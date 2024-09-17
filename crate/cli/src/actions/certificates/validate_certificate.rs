use std::path::PathBuf;

use clap::Parser;
use cosmian_kms_client::{
    cosmian_kmip::crypto::generic::kmip_requests::build_validate_certificate_request,
    kmip::kmip_types::ValidityIndicator, KmsClient,
};

use crate::{actions::console, error::result::CliResult};

/// Validate a certificate.
///
/// A certificate or a chain of certificates is validated.
/// It means that the certificate chain is valid in terms of time, well signed,
/// complete, and no components has been flagged as removed.
#[derive(Parser, Debug)]
pub struct ValidateCertificatesAction {
    /// One or more Certificates filepath.
    #[clap(long = "certificate", short = 'v')]
    certificate: Vec<PathBuf>,
    /// One or more Unique Identifiers of Certificate Objects.
    #[clap(long = "unique-identifier", short = 'k')]
    unique_identifier: Vec<String>,
    /// A Date-Time object indicating when the certificate chain needs to be
    /// valid. If omitted, the current date and time SHALL be assumed.
    #[clap(long = "validity-time", short = 't')]
    validity_time: Option<String>,
}

impl ValidateCertificatesAction {
    pub async fn run(&self, client_connector: &KmsClient) -> CliResult<()> {
        let request = build_validate_certificate_request(
            &self.certificate,
            &self.unique_identifier,
            self.validity_time.clone(),
        )?;
        let validity_indicator = client_connector.validate(request).await?.validity_indicator;
        console::Stdout::new(match validity_indicator {
            ValidityIndicator::Valid => "Valid",
            ValidityIndicator::Invalid => "Invalid",
            ValidityIndicator::Unknown => "Unknown",
        })
        .write()?;
        Ok(())
    }
}
