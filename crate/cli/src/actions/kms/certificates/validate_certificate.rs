use clap::Parser;
use cosmian_kms_client::{
    KmsClient,
    kmip_2_1::{kmip_types::ValidityIndicator, requests::build_validate_certificate_request},
};

use crate::{
    actions::kms::{console, labels::CERTIFICATE_ID},
    error::result::KmsCliResult,
};

/// Validate a certificate.
///
/// A certificate or a chain of certificates is validated.
/// It means that the certificate chain is valid in terms of time, well-signed,
/// complete, and no components have been flagged as removed.
#[derive(Parser, Default, Debug)]
pub struct ValidateCertificatesAction {
    /// One or more Unique Identifiers of Certificate Objects.
    #[clap(long = CERTIFICATE_ID, short = 'k')]
    pub(crate) certificate_id: Vec<String>,
    /// A Date-Time object indicating when the certificate chain needs to be
    /// valid. If omitted, the current date and time SHALL be assumed.
    #[clap(long = "validity-time", short = 't')]
    pub(crate) validity_time: Option<String>,
}

impl ValidateCertificatesAction {
    pub async fn run(&self, kms_rest_client: KmsClient) -> KmsCliResult<ValidityIndicator> {
        let request =
            build_validate_certificate_request(&self.certificate_id, self.validity_time.clone())?;
        let validity_indicator = kms_rest_client.validate(request).await?.validity_indicator;
        console::Stdout::new(match validity_indicator {
            ValidityIndicator::Valid => "Valid",
            ValidityIndicator::Invalid => "Invalid",
            ValidityIndicator::Unknown => "Unknown",
        })
        .write()?;
        Ok(validity_indicator)
    }
}
