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
) -> Result<(), CliError> {
    let request = build_validate_certificate_request(certificates, uids, date)?;
    let result = kms_rest_client.validate(request).await?;
    print_validity_indicator(result.validity_indicator);
    Ok(())
}

fn print_validity_indicator(vi: ValidityIndicator) {
    match vi {
        ValidityIndicator::Invalid => print!("certificate validity : invalid"),
        ValidityIndicator::Unknown => print!("certificate validity : unknown"),
        ValidityIndicator::Valid => print!("certificate validity : valid"),
    }
}
