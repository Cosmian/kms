use cosmian_kms_client::{
    cosmian_kmip::crypto::generic::kmip_requests::build_validate_certificate_request,
    kmip::kmip_types::ValidityIndicator, KmsClient,
};

use crate::error::CliError;

pub async fn validate(
    kms_rest_client: &KmsClient,
    certificates: Vec<String>,
    uids: Vec<String>,
    date: String,
) -> Result<String, CliError> {
    let request = build_validate_certificate_request(certificates, uids, date)?;
    let result = kms_rest_client.validate(request).await?;
    Ok({
        match result.validity_indicator {
            ValidityIndicator::Invalid => "Invalid".to_string(),
            ValidityIndicator::Unknown => "Unknown".to_string(),
            ValidityIndicator::Valid => "Valid".to_string(),
        }
    })
}
